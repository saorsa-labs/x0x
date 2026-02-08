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

    let percent_used = used_bytes.saturating_mul(100) / budget;
    if percent_used >= 100 {
        return match mode {
            PersistenceMode::Strict => BudgetDecision::StrictFailAtCapacity,
            PersistenceMode::Degraded => BudgetDecision::DegradedSkipAtCapacity,
        };
    }

    if percent_used >= u64::from(retention.critical_threshold_percent) {
        return BudgetDecision::Warning90;
    }

    if percent_used >= u64::from(retention.warning_threshold_percent) {
        return BudgetDecision::Warning80;
    }

    BudgetDecision::BelowWarning
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
