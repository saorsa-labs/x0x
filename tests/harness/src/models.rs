//! Reference model oracles for model-based testing.
//!
//! These are simplified, obviously-correct implementations that serve as
//! oracles against which we test the real x0x implementations.

use std::collections::{HashMap, HashSet};

// ── KV Model ────────────────────────────────────────────────────────────

/// Simple HashMap oracle for KV store testing.
#[derive(Debug, Clone, Default)]
pub struct KvModel {
    data: HashMap<String, Vec<u8>>,
}

impl KvModel {
    /// Create an empty KV model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite a key.
    pub fn put(&mut self, key: String, value: Vec<u8>) {
        self.data.insert(key, value);
    }

    /// Lookup a key.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.data.get(key)
    }

    /// Remove a key. Returns true if it existed.
    pub fn remove(&mut self, key: &str) -> bool {
        self.data.remove(key).is_some()
    }

    /// Sorted list of keys.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.data.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ── Trust Model ─────────────────────────────────────────────────────────

/// Trust level (mirrors x0x::contacts::TrustLevel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Blocked = 0,
    Unknown = 1,
    Known = 2,
    Trusted = 3,
}

/// Identity type (mirrors x0x::contacts::IdentityType).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    Anonymous,
    Known,
    Trusted,
    Pinned,
}

/// Trust evaluation decision (mirrors x0x::trust::TrustDecision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    Accept,
    AcceptWithFlag,
    RejectBlocked,
    RejectMachineMismatch,
    Unknown,
}

/// Contact record for the trust model.
#[derive(Debug, Clone)]
pub struct ContactRecord {
    pub trust_level: TrustLevel,
    pub identity_type: IdentityType,
    pub machines: HashSet<[u8; 32]>,
    pub pinned_machines: HashSet<[u8; 32]>,
}

/// Simple trust evaluation oracle.
#[derive(Debug, Clone, Default)]
pub struct TrustModel {
    contacts: HashMap<[u8; 32], ContactRecord>,
}

impl TrustModel {
    /// Create an empty trust model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a contact with Unknown trust.
    pub fn add_contact(&mut self, agent: [u8; 32]) {
        self.contacts.entry(agent).or_insert(ContactRecord {
            trust_level: TrustLevel::Unknown,
            identity_type: IdentityType::Anonymous,
            machines: HashSet::new(),
            pinned_machines: HashSet::new(),
        });
    }

    /// Remove a contact.
    pub fn remove_contact(&mut self, agent: &[u8; 32]) {
        self.contacts.remove(agent);
    }

    /// Set trust level for a contact.
    pub fn set_trust(&mut self, agent: &[u8; 32], level: TrustLevel) {
        if let Some(contact) = self.contacts.get_mut(agent) {
            contact.trust_level = level;
        }
    }

    /// Set identity type for a contact.
    pub fn set_identity_type(&mut self, agent: &[u8; 32], id_type: IdentityType) {
        if let Some(contact) = self.contacts.get_mut(agent) {
            contact.identity_type = id_type;
        }
    }

    /// Add a known machine for a contact.
    pub fn add_machine(&mut self, agent: &[u8; 32], machine: [u8; 32]) {
        if let Some(contact) = self.contacts.get_mut(agent) {
            contact.machines.insert(machine);
        }
    }

    /// Pin a machine for a contact.
    pub fn pin_machine(&mut self, agent: &[u8; 32], machine: [u8; 32]) {
        if let Some(contact) = self.contacts.get_mut(agent) {
            contact.pinned_machines.insert(machine);
        }
    }

    /// Evaluate trust for an (agent, machine) pair.
    ///
    /// Implements the same decision rules as x0x's TrustEvaluator:
    /// 1. Not in contacts → Unknown
    /// 2. Blocked → RejectBlocked
    /// 3. Pinned + wrong machine → RejectMachineMismatch
    /// 4. Pinned + right machine → Accept
    /// 5. Trusted → Accept
    /// 6. Known → AcceptWithFlag
    /// 7. Otherwise → Unknown
    pub fn evaluate(&self, agent: &[u8; 32], machine: &[u8; 32]) -> TrustDecision {
        let contact = match self.contacts.get(agent) {
            Some(c) => c,
            None => return TrustDecision::Unknown,
        };

        // Rule 2: Blocked
        if contact.trust_level == TrustLevel::Blocked {
            return TrustDecision::RejectBlocked;
        }

        // Rule 3-4: Pinned identity
        if contact.identity_type == IdentityType::Pinned {
            if contact.pinned_machines.contains(machine) {
                return TrustDecision::Accept;
            }
            return TrustDecision::RejectMachineMismatch;
        }

        // Rule 5: Trusted
        if contact.trust_level == TrustLevel::Trusted {
            return TrustDecision::Accept;
        }

        // Rule 6: Known
        if contact.trust_level == TrustLevel::Known {
            return TrustDecision::AcceptWithFlag;
        }

        // Rule 7: Unknown
        TrustDecision::Unknown
    }
}

// ── Task List Model ─────────────────────────────────────────────────────

/// Task state for the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Empty,
    Claimed,
    Done,
}

/// Task record for the model.
#[derive(Debug, Clone)]
pub struct TaskRecord {
    pub title: String,
    pub state: TaskState,
}

/// Simple task list oracle.
#[derive(Debug, Clone, Default)]
pub struct TaskListModel {
    tasks: HashMap<String, TaskRecord>,
    order: Vec<String>,
}

impl TaskListModel {
    /// Create an empty task list model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a task.
    pub fn add_task(&mut self, id: String, title: String) {
        if !self.tasks.contains_key(&id) {
            self.tasks.insert(
                id.clone(),
                TaskRecord {
                    title,
                    state: TaskState::Empty,
                },
            );
            self.order.push(id);
        }
    }

    /// Remove a task.
    pub fn remove_task(&mut self, id: &str) {
        self.tasks.remove(id);
        self.order.retain(|i| i != id);
    }

    /// Claim a task. Returns false if not in Empty state.
    pub fn claim_task(&mut self, id: &str) -> bool {
        if let Some(task) = self.tasks.get_mut(id) {
            if task.state == TaskState::Empty {
                task.state = TaskState::Claimed;
                return true;
            }
        }
        false
    }

    /// Complete a task. Returns false if not in Claimed state.
    pub fn complete_task(&mut self, id: &str) -> bool {
        if let Some(task) = self.tasks.get_mut(id) {
            if task.state == TaskState::Claimed {
                task.state = TaskState::Done;
                return true;
            }
        }
        false
    }

    /// Tasks in order.
    pub fn tasks(&self) -> Vec<(&str, &TaskRecord)> {
        self.order
            .iter()
            .filter_map(|id| self.tasks.get(id.as_str()).map(|t| (id.as_str(), t)))
            .collect()
    }

    /// Number of tasks.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_model_basic() {
        let mut kv = KvModel::new();
        kv.put("key1".into(), b"value1".to_vec());
        assert_eq!(kv.get("key1"), Some(&b"value1".to_vec()));
        assert_eq!(kv.keys(), vec!["key1"]);
        assert!(kv.remove("key1"));
        assert!(kv.is_empty());
    }

    #[test]
    fn trust_model_blocked_overrides_all() {
        let mut tm = TrustModel::new();
        let agent = [1u8; 32];
        let machine = [2u8; 32];
        tm.add_contact(agent);
        tm.set_trust(&agent, TrustLevel::Trusted);
        tm.set_trust(&agent, TrustLevel::Blocked);
        assert_eq!(tm.evaluate(&agent, &machine), TrustDecision::RejectBlocked);
    }

    #[test]
    fn trust_model_pinned_machine() {
        let mut tm = TrustModel::new();
        let agent = [1u8; 32];
        let good_machine = [2u8; 32];
        let bad_machine = [3u8; 32];
        tm.add_contact(agent);
        tm.set_identity_type(&agent, IdentityType::Pinned);
        tm.pin_machine(&agent, good_machine);
        assert_eq!(tm.evaluate(&agent, &good_machine), TrustDecision::Accept);
        assert_eq!(
            tm.evaluate(&agent, &bad_machine),
            TrustDecision::RejectMachineMismatch
        );
    }

    #[test]
    fn task_list_model_state_machine() {
        let mut tl = TaskListModel::new();
        tl.add_task("t1".into(), "Test".into());
        assert!(tl.claim_task("t1"));
        assert!(!tl.claim_task("t1")); // already claimed
        assert!(tl.complete_task("t1"));
        assert!(!tl.complete_task("t1")); // already done
    }
}
