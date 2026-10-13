//! #1229 stored-delivery refusal.
//!
//! Live pubsub drops a revoked or Blocked sender in `decode_for_delivery`.
//! Stored reads use the same agent checks. Direct-message replay also drops
//! a revoked originating machine and a revoked agent–machine binding, matching
//! live DM delivery.

use super::state::AppState;
use super::{parse_agent_id_hex, parse_machine_id_hex};
use crate::contacts::TrustLevel;
use crate::history::{HistoryRecord, Scope};

/// True when live pubsub delivery would drop this sender.
///
/// The check matches `decode_for_delivery`: the revocation set, then the
/// contact store's revoked keys, then `Blocked`. An author hex that does
/// not decode to an agent id returns false.
pub(in crate::server) async fn stored_sender_delivery_refused(
    state: &AppState,
    author_hex: &str,
) -> bool {
    let Ok(agent) = parse_agent_id_hex(author_hex) else {
        return false;
    };
    if state
        .agent
        .revocation_set()
        .read()
        .await
        .is_agent_revoked(&agent)
    {
        tracing::debug!(
            author = %author_hex,
            "stored delivery skipped: sender is revoked"
        );
        return true;
    }
    let contacts = state.contacts.read().await;
    if contacts.is_revoked(&agent) || contacts.trust_level(&agent) == TrustLevel::Blocked {
        tracing::debug!(
            author = %author_hex,
            "stored delivery skipped: sender is blocked"
        );
        return true;
    }
    false
}

/// True when a stored direct message must not be replayed.
///
/// Agent refusal matches pubsub delivery. A parsed `author_machine` is also
/// refused when that machine is revoked, or when the agent–machine binding
/// is revoked. That matches live DM delivery (`inbound_peer_revoked` and
/// the ADR-0043 pairing gate). A missing or unparseable id is not a refusal
/// by itself.
pub(in crate::server) async fn stored_dm_delivery_refused(
    state: &AppState,
    author_hex: Option<&str>,
    machine_hex: Option<&str>,
) -> bool {
    if let Some(author) = author_hex {
        if stored_sender_delivery_refused(state, author).await {
            return true;
        }
    }
    let Some(machine_hex) = machine_hex else {
        return false;
    };
    let Ok(machine) = parse_machine_id_hex(machine_hex) else {
        return false;
    };
    let set = state.agent.revocation_set();
    let revoked = set.read().await;
    if revoked.is_machine_revoked(&machine) {
        tracing::debug!(
            machine = %machine_hex,
            "stored DM skipped: originating machine is revoked"
        );
        return true;
    }
    if let Some(author_hex) = author_hex {
        if let Ok(author) = parse_agent_id_hex(author_hex) {
            if revoked.is_binding_revoked(&author, &machine) {
                tracing::debug!(
                    author = %author_hex,
                    machine = %machine_hex,
                    "stored DM skipped: agent-machine binding is revoked"
                );
                return true;
            }
        }
    }
    false
}

/// True when a history read must hide this row.
///
/// Direct-message rows use [`stored_dm_delivery_refused`]. Every other scope
/// uses the agent check only, matching live pubsub delivery. A row with no
/// author stays.
pub(in crate::server) async fn history_record_delivery_refused(
    state: &AppState,
    record: &HistoryRecord,
) -> bool {
    if matches!(record.scope, Scope::Dm(_)) {
        stored_dm_delivery_refused(
            state,
            record.author_agent.as_deref(),
            record.author_machine.as_deref(),
        )
        .await
    } else if let Some(author) = record.author_agent.as_deref() {
        stored_sender_delivery_refused(state, author).await
    } else {
        false
    }
}
