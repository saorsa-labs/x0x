//! ADR 0107 (r5; `docs/design/join-artifact-serving-lifecycle.md`, G6–G8):
//! fair, coalescing admission for join-artifact fetch handling.
//!
//! A fetch handler can wait on its group's membership lock. Shared, global
//! slots let one group whose lock is held (or one flooding requester) use
//! up the capacity every other group needs. [`FairAdmission`] admits a
//! handler only when its coalescing key is not already in flight, its group
//! is under a per-group cap, and the node is under a global cap. The
//! returned [`AdmissionTicket`] releases all three on drop (completion,
//! timeout, abort or panic).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct Inner {
    in_flight: HashSet<String>,
    per_group: HashMap<String, usize>,
    total: usize,
}

/// Why a fetch handler was not admitted. Every refusal is retryable: the
/// requester's own retry schedule asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum AdmissionRefusal {
    /// A handler for the same coalescing key is already in flight; it will
    /// serve this request too.
    Duplicate,
    /// This group already has its share of in-flight handlers.
    GroupAtCapacity,
    /// The node-wide handler cap is reached.
    AtCapacity,
}

/// Fair, coalescing admission (see the module docs).
#[derive(Debug)]
pub(in crate::server) struct FairAdmission {
    inner: Arc<Mutex<Inner>>,
    per_group_cap: usize,
    global_cap: usize,
}

/// An admitted fetch handler's hold on [`FairAdmission`]; dropping it
/// releases the key, the group share and the global slot.
#[derive(Debug)]
pub(in crate::server) struct AdmissionTicket {
    inner: Arc<Mutex<Inner>>,
    key: String,
    group: String,
}

impl FairAdmission {
    pub(in crate::server) fn new(per_group_cap: usize, global_cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            per_group_cap,
            global_cap,
        }
    }

    /// Admit a handler for `key` (the coalescing key) in `group`.
    pub(in crate::server) fn try_admit(
        &self,
        key: &str,
        group: &str,
    ) -> Result<AdmissionTicket, AdmissionRefusal> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.in_flight.contains(key) {
            return Err(AdmissionRefusal::Duplicate);
        }
        if inner.total >= self.global_cap {
            return Err(AdmissionRefusal::AtCapacity);
        }
        if inner.per_group.get(group).copied().unwrap_or(0) >= self.per_group_cap {
            return Err(AdmissionRefusal::GroupAtCapacity);
        }
        inner.in_flight.insert(key.to_string());
        *inner.per_group.entry(group.to_string()).or_insert(0) += 1;
        inner.total += 1;
        Ok(AdmissionTicket {
            inner: Arc::clone(&self.inner),
            key: key.to_string(),
            group: group.to_string(),
        })
    }

    /// In-flight handlers (diagnostics and tests).
    #[cfg(test)]
    pub(in crate::server) fn in_flight(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .total
    }
}

impl Drop for AdmissionTicket {
    fn drop(&mut self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !inner.in_flight.remove(&self.key) {
            return;
        }
        if let Some(count) = inner.per_group.get_mut(&self.group) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.per_group.remove(&self.group);
            }
        }
        inner.total = inner.total.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionRefusal, FairAdmission};

    #[test]
    fn duplicates_coalesce_and_groups_share_fairly() {
        let admission = FairAdmission::new(2, 3);
        let a1 = admission.try_admit("a1", "A").expect("first A");
        assert_eq!(
            admission.try_admit("a1", "A").err(),
            Some(AdmissionRefusal::Duplicate)
        );
        let a2 = admission.try_admit("a2", "A").expect("second A");
        assert_eq!(
            admission.try_admit("a3", "A").err(),
            Some(AdmissionRefusal::GroupAtCapacity)
        );
        let b1 = admission
            .try_admit("b1", "B")
            .expect("B is not starved by A");
        assert_eq!(
            admission.try_admit("c1", "C").err(),
            Some(AdmissionRefusal::AtCapacity)
        );
        drop(a1);
        let _c1 = admission
            .try_admit("c1", "C")
            .expect("a released slot is reusable");
        assert_eq!(admission.in_flight(), 3);
        drop((a2, b1));
        assert_eq!(admission.in_flight(), 1);
        let _a1_again = admission
            .try_admit("a1", "A")
            .expect("a released key is reusable");
    }
}
