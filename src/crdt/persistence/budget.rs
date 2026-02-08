use crate::crdt::persistence::policy::{PersistenceMode, RetentionPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDecision {
    BelowWarning,
    Warning80,
    Warning90,
    StrictFailAtCapacity,
    DegradedSkipAtCapacity,
}

#[must_use]
pub fn evaluate_budget(
    retention: &RetentionPolicy,
    mode: PersistenceMode,
    used_bytes: u64,
) -> BudgetDecision {
    let budget = retention.storage_budget_bytes;
    if budget == 0 {
        return match mode {
            PersistenceMode::Strict => BudgetDecision::StrictFailAtCapacity,
            PersistenceMode::Degraded => BudgetDecision::DegradedSkipAtCapacity,
        };
    }

    if used_bytes >= budget {
        return match mode {
            PersistenceMode::Strict => BudgetDecision::StrictFailAtCapacity,
            PersistenceMode::Degraded => BudgetDecision::DegradedSkipAtCapacity,
        };
    }

    if reaches_threshold(used_bytes, budget, retention.critical_threshold_percent) {
        return BudgetDecision::Warning90;
    }

    if reaches_threshold(used_bytes, budget, retention.warning_threshold_percent) {
        return BudgetDecision::Warning80;
    }

    BudgetDecision::BelowWarning
}

fn reaches_threshold(used_bytes: u64, budget: u64, threshold_percent: u8) -> bool {
    u128::from(used_bytes) * 100 >= u128::from(budget) * u128::from(threshold_percent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::persistence::policy::RetentionPolicy;

    #[test]
    fn budget_thresholds_follow_defaults() {
        let retention = RetentionPolicy::default();
        let budget = retention.storage_budget_bytes;

        assert_eq!(
            evaluate_budget(&retention, PersistenceMode::Degraded, budget * 79 / 100),
            BudgetDecision::BelowWarning
        );
        assert_eq!(
            evaluate_budget(&retention, PersistenceMode::Degraded, budget * 80 / 100),
            BudgetDecision::Warning80
        );
        assert_eq!(
            evaluate_budget(&retention, PersistenceMode::Degraded, budget * 90 / 100),
            BudgetDecision::Warning90
        );
    }
}
