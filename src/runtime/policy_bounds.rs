//! Host policy envelope bounds for runtime-adjustable persistence controls.

use crate::config::HostPolicyEnvelopeConfig;
use crate::crdt::persistence::{CheckpointPolicy, PersistencePolicy};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCheckpointPolicyUpdate {
    pub mutation_threshold: Option<u32>,
    pub dirty_time_floor: Option<Duration>,
    pub debounce_floor: Option<Duration>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PolicyBoundsError {
    #[error("host envelope mutation threshold bounds invalid: min={min}, max={max}")]
    InvalidMutationThresholdBounds { min: u32, max: u32 },
    #[error("host envelope dirty-time bounds invalid: min={min}, max={max}")]
    InvalidDirtyTimeBounds { min: u64, max: u64 },
    #[error("host envelope debounce bounds invalid: min={min}, max={max}")]
    InvalidDebounceBounds { min: u64, max: u64 },
    #[error("runtime checkpoint adjustment is not allowed by host envelope")]
    RuntimeCheckpointAdjustmentNotAllowed,
    #[error("mutation threshold {value} out of host bounds [{min}, {max}]")]
    MutationThresholdOutOfBounds { value: u32, min: u32, max: u32 },
    #[error("dirty-time floor {value}s out of host bounds [{min}s, {max}s]")]
    DirtyTimeFloorOutOfBounds { value: u64, min: u64, max: u64 },
    #[error("debounce floor {value}s out of host bounds [{min}s, {max}s]")]
    DebounceFloorOutOfBounds { value: u64, min: u64, max: u64 },
}

pub fn validate_host_envelope(
    envelope: &HostPolicyEnvelopeConfig,
) -> Result<(), PolicyBoundsError> {
    if envelope.min_mutation_threshold == 0
        || envelope.max_mutation_threshold == 0
        || envelope.min_mutation_threshold > envelope.max_mutation_threshold
    {
        return Err(PolicyBoundsError::InvalidMutationThresholdBounds {
            min: envelope.min_mutation_threshold,
            max: envelope.max_mutation_threshold,
        });
    }

    if envelope.min_dirty_time_floor_secs == 0
        || envelope.max_dirty_time_floor_secs == 0
        || envelope.min_dirty_time_floor_secs > envelope.max_dirty_time_floor_secs
    {
        return Err(PolicyBoundsError::InvalidDirtyTimeBounds {
            min: envelope.min_dirty_time_floor_secs,
            max: envelope.max_dirty_time_floor_secs,
        });
    }

    if envelope.min_debounce_floor_secs == 0
        || envelope.max_debounce_floor_secs == 0
        || envelope.min_debounce_floor_secs > envelope.max_debounce_floor_secs
    {
        return Err(PolicyBoundsError::InvalidDebounceBounds {
            min: envelope.min_debounce_floor_secs,
            max: envelope.max_debounce_floor_secs,
        });
    }

    if !envelope.allow_runtime_checkpoint_frequency_adjustment
        && (envelope.min_mutation_threshold != envelope.max_mutation_threshold
            || envelope.min_dirty_time_floor_secs != envelope.max_dirty_time_floor_secs
            || envelope.min_debounce_floor_secs != envelope.max_debounce_floor_secs)
    {
        return Err(PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed);
    }

    Ok(())
}

pub fn ensure_policy_within_envelope(
    policy: &PersistencePolicy,
    envelope: &HostPolicyEnvelopeConfig,
) -> Result<(), PolicyBoundsError> {
    if policy.checkpoint.mutation_threshold < envelope.min_mutation_threshold
        || policy.checkpoint.mutation_threshold > envelope.max_mutation_threshold
    {
        return Err(PolicyBoundsError::MutationThresholdOutOfBounds {
            value: policy.checkpoint.mutation_threshold,
            min: envelope.min_mutation_threshold,
            max: envelope.max_mutation_threshold,
        });
    }

    let dirty_time_floor = policy.checkpoint.dirty_time_floor.as_secs();
    if dirty_time_floor < envelope.min_dirty_time_floor_secs
        || dirty_time_floor > envelope.max_dirty_time_floor_secs
    {
        return Err(PolicyBoundsError::DirtyTimeFloorOutOfBounds {
            value: dirty_time_floor,
            min: envelope.min_dirty_time_floor_secs,
            max: envelope.max_dirty_time_floor_secs,
        });
    }

    let debounce_floor = policy.checkpoint.debounce_floor.as_secs();
    if debounce_floor < envelope.min_debounce_floor_secs
        || debounce_floor > envelope.max_debounce_floor_secs
    {
        return Err(PolicyBoundsError::DebounceFloorOutOfBounds {
            value: debounce_floor,
            min: envelope.min_debounce_floor_secs,
            max: envelope.max_debounce_floor_secs,
        });
    }

    Ok(())
}

pub fn apply_checkpoint_frequency_update(
    policy: &PersistencePolicy,
    envelope: &HostPolicyEnvelopeConfig,
    update: &RuntimeCheckpointPolicyUpdate,
) -> Result<PersistencePolicy, PolicyBoundsError> {
    let next_checkpoint = apply_checkpoint_frequency_update_to_checkpoint_policy(
        &policy.checkpoint,
        envelope,
        update,
    )?;

    let mut next = policy.clone();
    next.checkpoint = next_checkpoint;
    Ok(next)
}

pub fn apply_checkpoint_frequency_update_to_checkpoint_policy(
    checkpoint: &CheckpointPolicy,
    envelope: &HostPolicyEnvelopeConfig,
    update: &RuntimeCheckpointPolicyUpdate,
) -> Result<CheckpointPolicy, PolicyBoundsError> {
    validate_host_envelope(envelope)?;

    if !envelope.allow_runtime_checkpoint_frequency_adjustment
        && (update.mutation_threshold.is_some()
            || update.dirty_time_floor.is_some()
            || update.debounce_floor.is_some())
    {
        return Err(PolicyBoundsError::RuntimeCheckpointAdjustmentNotAllowed);
    }

    let mut next = checkpoint.clone();

    if let Some(mutation_threshold) = update.mutation_threshold {
        if mutation_threshold < envelope.min_mutation_threshold
            || mutation_threshold > envelope.max_mutation_threshold
        {
            return Err(PolicyBoundsError::MutationThresholdOutOfBounds {
                value: mutation_threshold,
                min: envelope.min_mutation_threshold,
                max: envelope.max_mutation_threshold,
            });
        }

        next.mutation_threshold = mutation_threshold;
    }

    if let Some(dirty_time_floor) = update.dirty_time_floor {
        let seconds = dirty_time_floor.as_secs();
        if seconds < envelope.min_dirty_time_floor_secs
            || seconds > envelope.max_dirty_time_floor_secs
        {
            return Err(PolicyBoundsError::DirtyTimeFloorOutOfBounds {
                value: seconds,
                min: envelope.min_dirty_time_floor_secs,
                max: envelope.max_dirty_time_floor_secs,
            });
        }

        next.dirty_time_floor = dirty_time_floor;
    }

    if let Some(debounce_floor) = update.debounce_floor {
        let seconds = debounce_floor.as_secs();
        if seconds < envelope.min_debounce_floor_secs || seconds > envelope.max_debounce_floor_secs
        {
            return Err(PolicyBoundsError::DebounceFloorOutOfBounds {
                value: seconds,
                min: envelope.min_debounce_floor_secs,
                max: envelope.max_debounce_floor_secs,
            });
        }

        next.debounce_floor = debounce_floor;
    }

    Ok(next)
}
