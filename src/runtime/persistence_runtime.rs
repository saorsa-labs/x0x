//! Runtime persistence policy state derived from startup configuration.

use crate::config::{ConfigError, HostPolicyEnvelopeConfig, StartupConfig};
use crate::crdt::persistence::PersistencePolicy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnabledPersistenceRuntime {
    pub policy: PersistencePolicy,
    pub host_policy: HostPolicyEnvelopeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceRuntime {
    Disabled,
    Enabled(EnabledPersistenceRuntime),
}

impl PersistenceRuntime {
    pub fn from_startup_config(config: &StartupConfig) -> Result<Self, ConfigError> {
        let resolved = config.resolve_persistence()?;

        if !resolved.policy.enabled {
            return Ok(Self::Disabled);
        }

        Ok(Self::Enabled(EnabledPersistenceRuntime {
            policy: resolved.policy,
            host_policy: resolved.host_policy,
        }))
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    #[must_use]
    pub fn policy(&self) -> Option<&PersistencePolicy> {
        match self {
            Self::Disabled => None,
            Self::Enabled(runtime) => Some(&runtime.policy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostPolicyEnvelopeConfig, PersistenceConfig};
    use crate::crdt::persistence::PersistenceMode;
    use std::time::Duration;

    #[test]
    fn disabled_config_keeps_runtime_on_disabled_path() {
        let runtime = PersistenceRuntime::from_startup_config(&StartupConfig::default()).unwrap();
        assert_eq!(runtime, PersistenceRuntime::Disabled);
        assert!(!runtime.is_enabled());
    }

    #[test]
    fn enabled_config_resolves_complete_policy() {
        let startup = StartupConfig {
            persistence: PersistenceConfig {
                enabled: true,
                strict_initialize_if_missing: Some(true),
                mode: Some("strict".to_string()),
                checkpoint_mutation_threshold: Some(64),
                checkpoint_dirty_time_floor_secs: Some(900),
                checkpoint_debounce_floor_secs: Some(4),
                retention_checkpoints_to_keep: Some(5),
                retention_storage_budget_bytes: Some(512 * 1024 * 1024),
                retention_warning_threshold_percent: Some(70),
                retention_critical_threshold_percent: Some(85),
                host_policy: HostPolicyEnvelopeConfig {
                    allow_runtime_checkpoint_frequency_adjustment: true,
                    min_mutation_threshold: 32,
                    max_mutation_threshold: 256,
                    min_dirty_time_floor_secs: 300,
                    max_dirty_time_floor_secs: 1_200,
                    min_debounce_floor_secs: 2,
                    max_debounce_floor_secs: 8,
                },
            },
        };

        let runtime = PersistenceRuntime::from_startup_config(&startup).unwrap();
        let Some(policy) = runtime.policy() else {
            panic!("expected enabled persistence runtime")
        };

        assert_eq!(policy.mode, PersistenceMode::Strict);
        assert_eq!(policy.checkpoint.mutation_threshold, 64);
        assert_eq!(policy.checkpoint.dirty_time_floor, Duration::from_secs(900));
        assert_eq!(policy.checkpoint.debounce_floor, Duration::from_secs(4));
        assert_eq!(policy.retention.checkpoints_to_keep, 5);
        assert_eq!(policy.retention.storage_budget_bytes, 512 * 1024 * 1024);
        assert_eq!(policy.retention.warning_threshold_percent, 70);
        assert_eq!(policy.retention.critical_threshold_percent, 85);
        assert!(policy.strict_initialization.initialize_if_missing);
    }
}
