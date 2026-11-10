//! Issue #1840 (ask 4): the typed outcome an authority sends back when its
//! validation refuses a `JoinRequestCreated` offer.
//!
//! The offer is a typed DM that carries the requester-signed V2 envelope.
//! When the authority refuses it before any roster write, the requester
//! used to learn nothing. This module is the one definition of the reply:
//! a typed DM (`x0x-group-join-outcome-v1\0` ‖ JSON [`JoinRequestOutcome`]).
//!
//! The outcome has no signature of its own. The DM envelope authenticates
//! the sender agent, and the requester accepts an outcome only from the
//! authority it sent that offer to, and only when `group_id`, `request_id`
//! and `envelope_digest` all equal its own pending offer. The digest covers
//! the exact signed envelope, so an outcome for one offer cannot be moved
//! to another request or to a re-sealed envelope of the same request.
//!
//! The body is JSON without `deny_unknown_fields`: a later optional field
//! is ignored by this release. An unknown `reason` decodes to
//! [`JoinRequestRefusalReason::Unknown`], which is terminal.

use serde::{Deserialize, Serialize};

/// Versioned, NUL-terminated DM prefix of a join-request outcome.
pub const JOIN_REQUEST_OUTCOME_DM_PREFIX: &[u8] = b"x0x-group-join-outcome-v1\0";

/// Upper bound on one encoded outcome, prefix included. A real outcome is
/// about 250 bytes.
pub const MAX_JOIN_REQUEST_OUTCOME_BYTES: usize = 1024;

/// Why the authority refused the request. A closed set: it names facts
/// about the requester or its envelope only, never another member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JoinRequestRefusalReason {
    /// The signed commit is at or behind the authority's revision.
    StaleHead,
    /// The signed commit does not chain to, or does not hash to, the
    /// authority's current state (for example a stub roster).
    StateMismatch,
    /// The group does not admit by request.
    NotRequestAccess,
    /// The requester already holds an active seat.
    AlreadyMember,
    /// The requester is banned from the group.
    Banned,
    /// The authority already holds a pending request from this requester.
    PendingExists,
    /// Any other validation refusal of the envelope.
    Invalid,
    /// A reason this release does not know, from a newer authority. Never
    /// encoded.
    #[serde(other, skip_serializing)]
    Unknown,
}

impl JoinRequestRefusalReason {
    /// The stable API and wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleHead => "stale_head",
            Self::StateMismatch => "state_mismatch",
            Self::NotRequestAccess => "not_request_access",
            Self::AlreadyMember => "already_member",
            Self::Banned => "banned",
            Self::PendingExists => "pending_exists",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }

    /// `true` when a NEW envelope, sealed over the authority's current
    /// head, can succeed. The same envelope is never worth another offer.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::StaleHead | Self::StateMismatch)
    }
}

/// The body of a join-request outcome DM. Today the only outcome is a
/// refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestOutcome {
    /// Stable group id of the refused request.
    pub group_id: String,
    /// The refused request id.
    pub request_id: String,
    /// Hex blake3 digest of the refused requester-signed V2 envelope.
    pub envelope_digest: String,
    /// Why the authority refused it.
    pub reason: JoinRequestRefusalReason,
}

impl JoinRequestOutcome {
    /// Encode the DM payload (prefix ‖ JSON).
    ///
    /// # Errors
    /// The reason is `Unknown`, the body does not encode, or the payload is
    /// over [`MAX_JOIN_REQUEST_OUTCOME_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.reason == JoinRequestRefusalReason::Unknown {
            return Err("an unknown refusal reason is never sent".to_string());
        }
        let body = serde_json::to_vec(self).map_err(|e| format!("encode: {e}"))?;
        let mut out = Vec::with_capacity(JOIN_REQUEST_OUTCOME_DM_PREFIX.len() + body.len());
        out.extend_from_slice(JOIN_REQUEST_OUTCOME_DM_PREFIX);
        out.extend_from_slice(&body);
        if out.len() > MAX_JOIN_REQUEST_OUTCOME_BYTES {
            return Err("join-request outcome over bound".to_string());
        }
        Ok(out)
    }

    /// Decode a DM payload. `None` for a wrong prefix, an oversized payload
    /// or a body that is not an outcome.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() > MAX_JOIN_REQUEST_OUTCOME_BYTES {
            return None;
        }
        let body = payload.strip_prefix(JOIN_REQUEST_OUTCOME_DM_PREFIX)?;
        serde_json::from_slice(body).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue1840_outcome_round_trips_and_ignores_later_fields() {
        let outcome = JoinRequestOutcome {
            group_id: "g".to_string(),
            request_id: "r".to_string(),
            envelope_digest: "ab".repeat(32),
            reason: JoinRequestRefusalReason::StaleHead,
        };
        let payload = outcome.encode().expect("encode");
        assert_eq!(JoinRequestOutcome::decode(&payload), Some(outcome));

        let mut later = JOIN_REQUEST_OUTCOME_DM_PREFIX.to_vec();
        later.extend_from_slice(
            br#"{"group_id":"g","request_id":"r","envelope_digest":"00","reason":"from_the_future","head":{"revision":7}}"#,
        );
        let decoded = JoinRequestOutcome::decode(&later).expect("a later optional field decodes");
        assert_eq!(decoded.reason, JoinRequestRefusalReason::Unknown);
        assert!(!decoded.reason.is_retryable());
        assert!(decoded.encode().is_err(), "Unknown is never sent");
        assert!(JoinRequestOutcome::decode(b"ordinary text").is_none());
    }
}
