//! Checkbox state machine for task items.
//!
//! Implements the state transitions for task checkboxes:
//! - Empty → Claimed (agent claims a task)
//! - Claimed → Done (agent completes a task)
//!
//! Invalid transitions return errors.

use crate::identity::AgentId;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Result type for checkbox operations.
pub type Result<T> = std::result::Result<T, CheckboxError>;

/// Errors that can occur during checkbox state transitions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckboxError {
    /// Attempted to claim an already-claimed task.
    #[error("task already claimed by {0}")]
    AlreadyClaimed(AgentId),

    /// Attempted to transition from Done state (immutable).
    #[error("task is already done and cannot be modified")]
    AlreadyDone,

    /// Attempted to complete without claiming first.
    #[error("task must be claimed before completion")]
    MustClaimFirst,
}

/// Checkbox state for a task item.
///
/// Represents the lifecycle of a task:
/// - `Empty`: Task is available for claiming
/// - `Claimed`: Task is claimed by an agent (in progress)
/// - `Done`: Task is completed by an agent (final state)
///
/// # State Machine
///
/// ```text
/// Empty ──claim──> Claimed ──complete──> Done
///   │                                      │
///   └──────────── (immutable) ─────────────┘
/// ```
///
/// # Concurrent Claims
///
/// When using OR-Set semantics, concurrent claims from different agents
/// can both succeed. The state machine handles this through timestamp-based
/// conflict resolution. The claim with the earliest timestamp wins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CheckboxState {
    /// Task is not claimed by anyone.
    Empty,

    /// Task is claimed by an agent.
    Claimed {
        /// The agent who claimed this task.
        agent_id: AgentId,
        /// When the task was claimed (Unix timestamp in milliseconds).
        timestamp: u64,
    },

    /// Task is completed.
    Done {
        /// The agent who completed this task.
        agent_id: AgentId,
        /// When the task was completed (Unix timestamp in milliseconds).
        timestamp: u64,
    },
}

impl CheckboxState {
    /// Create a new Claimed state.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent claiming the task
    /// * `timestamp` - The claim timestamp (Unix milliseconds)
    ///
    /// # Returns
    ///
    /// A Claimed state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent_id = AgentId([1u8; 32]);
    /// let timestamp = 1234567890;
    /// let state = CheckboxState::claim(agent_id, timestamp)?;
    /// assert!(state.is_claimed());
    /// ```
    pub fn claim(agent_id: AgentId, timestamp: u64) -> Result<Self> {
        Ok(Self::Claimed {
            agent_id,
            timestamp,
        })
    }

    /// Create a new Done state.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The agent completing the task
    /// * `timestamp` - The completion timestamp (Unix milliseconds)
    ///
    /// # Returns
    ///
    /// A Done state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let agent_id = AgentId([1u8; 32]);
    /// let timestamp = 1234567890;
    /// let state = CheckboxState::complete(agent_id, timestamp)?;
    /// assert!(state.is_done());
    /// ```
    pub fn complete(agent_id: AgentId, timestamp: u64) -> Result<Self> {
        Ok(Self::Done {
            agent_id,
            timestamp,
        })
    }

    /// Check if the checkbox is empty (unclaimed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Check if the checkbox is claimed.
    #[must_use]
    pub fn is_claimed(&self) -> bool {
        matches!(self, Self::Claimed { .. })
    }

    /// Check if the checkbox is done (completed).
    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done { .. })
    }

    /// Get the agent who claimed this task, if any.
    ///
    /// Returns `Some(agent_id)` if the state is Claimed or Done,
    /// otherwise `None`.
    #[must_use]
    pub fn claimed_by(&self) -> Option<&AgentId> {
        match self {
            Self::Empty => None,
            Self::Claimed { agent_id, .. } | Self::Done { agent_id, .. } => Some(agent_id),
        }
    }

    /// Get the timestamp of this state, if any.
    ///
    /// Returns `Some(timestamp)` if the state is Claimed or Done,
    /// otherwise `None`.
    #[must_use]
    pub fn timestamp(&self) -> Option<u64> {
        match self {
            Self::Empty => None,
            Self::Claimed { timestamp, .. } | Self::Done { timestamp, .. } => Some(*timestamp),
        }
    }

    /// Attempt to transition from this state to Claimed.
    ///
    /// # State Transitions
    ///
    /// - `Empty -> Claimed`: OK
    /// - `Claimed -> Claimed`: Error (already claimed)
    /// - `Done -> Claimed`: Error (immutable)
    ///
    /// # Errors
    ///
    /// Returns an error if the transition is invalid.
    pub fn transition_to_claimed(&self, agent_id: AgentId, timestamp: u64) -> Result<Self> {
        match self {
            Self::Empty => Ok(Self::Claimed {
                agent_id,
                timestamp,
            }),
            Self::Claimed {
                agent_id: existing_agent,
                ..
            } => Err(CheckboxError::AlreadyClaimed(*existing_agent)),
            Self::Done { .. } => Err(CheckboxError::AlreadyDone),
        }
    }

    /// Attempt to transition from this state to Done.
    ///
    /// # State Transitions
    ///
    /// - `Empty -> Done`: Error (must claim first)
    /// - `Claimed -> Done`: OK
    /// - `Done -> Done`: Error (immutable)
    ///
    /// # Errors
    ///
    /// Returns an error if the transition is invalid.
    pub fn transition_to_done(&self, agent_id: AgentId, timestamp: u64) -> Result<Self> {
        match self {
            Self::Empty => Err(CheckboxError::MustClaimFirst),
            Self::Claimed { .. } => Ok(Self::Done {
                agent_id,
                timestamp,
            }),
            Self::Done { .. } => Err(CheckboxError::AlreadyDone),
        }
    }
}

/// Implement Ord for deterministic tiebreaking in concurrent scenarios.
///
/// Ordering rules:
/// 1. Empty < Claimed < Done (by variant)
/// 2. Within Claimed/Done: earlier timestamp < later timestamp
/// 3. If timestamps equal: lexicographic ordering of agent_id bytes
impl Ord for CheckboxState {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Empty, Self::Empty) => Ordering::Equal,
            (Self::Empty, _) => Ordering::Less,
            (_, Self::Empty) => Ordering::Greater,

            (
                Self::Claimed {
                    agent_id: aid1,
                    timestamp: ts1,
                },
                Self::Claimed {
                    agent_id: aid2,
                    timestamp: ts2,
                },
            ) => match ts1.cmp(ts2) {
                Ordering::Equal => aid1.as_bytes().cmp(aid2.as_bytes()),
                ordering => ordering,
            },

            (Self::Claimed { .. }, Self::Done { .. }) => Ordering::Less,
            (Self::Done { .. }, Self::Claimed { .. }) => Ordering::Greater,

            (
                Self::Done {
                    agent_id: aid1,
                    timestamp: ts1,
                },
                Self::Done {
                    agent_id: aid2,
                    timestamp: ts2,
                },
            ) => match ts1.cmp(ts2) {
                Ordering::Equal => aid1.as_bytes().cmp(aid2.as_bytes()),
                ordering => ordering,
            },
        }
    }
}

impl PartialOrd for CheckboxState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn test_checkbox_state_constructors() {
        let agent = agent(1);
        let timestamp = 1000;

        let claimed = CheckboxState::claim(agent, timestamp).ok().unwrap();
        assert!(claimed.is_claimed());
        assert_eq!(claimed.claimed_by(), Some(&agent));
        assert_eq!(claimed.timestamp(), Some(timestamp));

        let done = CheckboxState::complete(agent, timestamp).ok().unwrap();
        assert!(done.is_done());
        assert_eq!(done.claimed_by(), Some(&agent));
        assert_eq!(done.timestamp(), Some(timestamp));
    }

    #[test]
    fn test_checkbox_state_predicates() {
        let agent = agent(1);

        let empty = CheckboxState::Empty;
        assert!(empty.is_empty());
        assert!(!empty.is_claimed());
        assert!(!empty.is_done());
        assert_eq!(empty.claimed_by(), None);
        assert_eq!(empty.timestamp(), None);

        let claimed = CheckboxState::claim(agent, 1000).ok().unwrap();
        assert!(!claimed.is_empty());
        assert!(claimed.is_claimed());
        assert!(!claimed.is_done());

        let done = CheckboxState::complete(agent, 2000).ok().unwrap();
        assert!(!done.is_empty());
        assert!(!done.is_claimed());
        assert!(done.is_done());
    }

    #[test]
    fn test_valid_transition_empty_to_claimed() {
        let empty = CheckboxState::Empty;
        let agent = agent(1);
        let timestamp = 1000;

        let claimed = empty.transition_to_claimed(agent, timestamp).ok().unwrap();
        assert!(claimed.is_claimed());
        assert_eq!(claimed.claimed_by(), Some(&agent));
    }

    #[test]
    fn test_valid_transition_claimed_to_done() {
        let agent1 = agent(1);
        let agent2 = agent(2);
        let claimed = CheckboxState::claim(agent1, 1000).ok().unwrap();

        // Same agent can complete
        let done1 = claimed.transition_to_done(agent1, 2000).ok().unwrap();
        assert!(done1.is_done());
        assert_eq!(done1.claimed_by(), Some(&agent1));

        // Different agent can also complete (task reassignment scenario)
        let done2 = claimed.transition_to_done(agent2, 2000).ok().unwrap();
        assert!(done2.is_done());
        assert_eq!(done2.claimed_by(), Some(&agent2));
    }

    #[test]
    fn test_invalid_transition_empty_to_done() {
        let empty = CheckboxState::Empty;
        let agent = agent(1);

        let result = empty.transition_to_done(agent, 1000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CheckboxError::MustClaimFirst);
    }

    #[test]
    fn test_invalid_transition_claimed_to_claimed() {
        let agent1 = agent(1);
        let agent2 = agent(2);
        let claimed = CheckboxState::claim(agent1, 1000).ok().unwrap();

        let result = claimed.transition_to_claimed(agent2, 2000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CheckboxError::AlreadyClaimed(agent1));
    }

    #[test]
    fn test_invalid_transition_from_done() {
        let agent1 = agent(1);
        let agent2 = agent(2);
        let done = CheckboxState::complete(agent1, 1000).ok().unwrap();

        // Cannot claim after done
        let result = done.transition_to_claimed(agent2, 2000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CheckboxError::AlreadyDone);

        // Cannot complete again
        let result = done.transition_to_done(agent2, 2000);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CheckboxError::AlreadyDone);
    }

    #[test]
    fn test_checkbox_ord_by_variant() {
        let empty = CheckboxState::Empty;
        let claimed = CheckboxState::claim(agent(1), 1000).ok().unwrap();
        let done = CheckboxState::complete(agent(1), 2000).ok().unwrap();

        // Empty < Claimed < Done
        assert!(empty < claimed);
        assert!(claimed < done);
        assert!(empty < done);
    }

    #[test]
    fn test_checkbox_ord_by_timestamp() {
        let agent = agent(1);
        let claimed_early = CheckboxState::claim(agent, 1000).ok().unwrap();
        let claimed_late = CheckboxState::claim(agent, 2000).ok().unwrap();

        assert!(claimed_early < claimed_late);

        let done_early = CheckboxState::complete(agent, 1000).ok().unwrap();
        let done_late = CheckboxState::complete(agent, 2000).ok().unwrap();

        assert!(done_early < done_late);
    }

    #[test]
    fn test_checkbox_ord_by_agent_id_tiebreak() {
        let agent1 = agent(1);
        let agent2 = agent(2);
        let timestamp = 1000;

        let claimed1 = CheckboxState::claim(agent1, timestamp).ok().unwrap();
        let claimed2 = CheckboxState::claim(agent2, timestamp).ok().unwrap();

        // When timestamps are equal, compare agent IDs lexicographically
        assert!(claimed1 < claimed2);

        let done1 = CheckboxState::complete(agent1, timestamp).ok().unwrap();
        let done2 = CheckboxState::complete(agent2, timestamp).ok().unwrap();

        assert!(done1 < done2);
    }

    #[test]
    fn test_checkbox_equality() {
        let agent = agent(1);
        let timestamp = 1000;

        let claimed1 = CheckboxState::claim(agent, timestamp).ok().unwrap();
        let claimed2 = CheckboxState::claim(agent, timestamp).ok().unwrap();
        assert_eq!(claimed1, claimed2);

        let done1 = CheckboxState::complete(agent, timestamp).ok().unwrap();
        let done2 = CheckboxState::complete(agent, timestamp).ok().unwrap();
        assert_eq!(done1, done2);
    }

    #[test]
    fn test_concurrent_claims_resolution() {
        // Simulate concurrent claims from two agents at different times
        let agent1 = agent(1);
        let agent2 = agent(2);

        let claim1 = CheckboxState::claim(agent1, 1000).ok().unwrap();
        let claim2 = CheckboxState::claim(agent2, 1100).ok().unwrap();

        // Earlier claim wins via Ord
        assert!(claim1 < claim2);

        // Same timestamp - agent ID tiebreaker
        let claim3 = CheckboxState::claim(agent1, 1000).ok().unwrap();
        let claim4 = CheckboxState::claim(agent2, 1000).ok().unwrap();
        assert!(claim3 < claim4); // agent1 < agent2 lexicographically
    }

    #[test]
    fn test_serialization_roundtrip() {
        let agent = agent(42);
        let timestamp = 1234567890;

        let states = vec![
            CheckboxState::Empty,
            CheckboxState::claim(agent, timestamp).ok().unwrap(),
            CheckboxState::complete(agent, timestamp).ok().unwrap(),
        ];

        for state in states {
            let serialized = bincode::serialize(&state).ok().unwrap();
            let deserialized: CheckboxState = bincode::deserialize(&serialized).ok().unwrap();
            assert_eq!(state, deserialized);
        }
    }
}
