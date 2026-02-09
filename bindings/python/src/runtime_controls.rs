use super::health::{BindingCheckpointFrequency, BindingPersistenceObservability};
use x0x::crdt::persistence::{CheckpointFrequencyUpdateRequest, PersistenceBackend};
use x0x::runtime::{AgentApiError, AgentCheckpointApi, PolicyBoundsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCheckpointFrequencyUpdateRequest {
    pub mutation_threshold: Option<u32>,
    pub dirty_time_floor_secs: Option<u64>,
    pub debounce_floor_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingInvalidRequestError {
    pub code: String,
    pub message: String,
}

pub fn query_persistence_observability<B: PersistenceBackend>(
    api: &AgentCheckpointApi<B>,
) -> BindingPersistenceObservability {
    super::health::map_persistence_observability(&api.observability_contract())
}

pub fn request_checkpoint_frequency_adjustment<B: PersistenceBackend>(
    api: &mut AgentCheckpointApi<B>,
    request: BindingCheckpointFrequencyUpdateRequest,
) -> Result<BindingCheckpointFrequency, BindingInvalidRequestError> {
    let updated = api
        .request_checkpoint_frequency_update(CheckpointFrequencyUpdateRequest {
            mutation_threshold: request.mutation_threshold,
            dirty_time_floor_secs: request.dirty_time_floor_secs,
            debounce_floor_secs: request.debounce_floor_secs,
        })
        .map_err(map_agent_api_error)?;

    Ok(BindingCheckpointFrequency {
        mutation_threshold: updated.mutation_threshold,
        dirty_time_floor_secs: updated.dirty_time_floor_secs,
        debounce_floor_secs: updated.debounce_floor_secs,
    })
}

fn map_agent_api_error(error: AgentApiError) -> BindingInvalidRequestError {
    match error {
        AgentApiError::PolicyBounds(bounds) => BindingInvalidRequestError {
            code: policy_bounds_code(&bounds).to_string(),
            message: bounds.to_string(),
        },
        AgentApiError::Backend(backend) => BindingInvalidRequestError {
            code: "backend_error".to_string(),
            message: backend.to_string(),
        },
    }
}

fn policy_bounds_code(error: &PolicyBoundsError) -> &'static str {
    match error {
        PolicyBoundsError::InvalidMutationThresholdBounds { .. }
        | PolicyBoundsError::InvalidDirtyTimeBounds { .. }
        | PolicyBoundsError::InvalidDebounceBounds { .. } => "invalid_host_policy_envelope",
        PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed => {
            "runtime_checkpoint_adjustment_not_allowed"
        }
        PolicyBoundsError::MutationThresholdOutOfBounds { .. } => {
            "mutation_threshold_out_of_bounds"
        }
        PolicyBoundsError::DirtyTimeFloorOutOfBounds { .. } => "dirty_time_floor_out_of_bounds",
        PolicyBoundsError::DebounceFloorOutOfBounds { .. } => "debounce_floor_out_of_bounds",
    }
}
