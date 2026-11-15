//! Typed `system.*` events on `GET /events` and `/ws` (#1351, Goal M M1).
//!
//! The 5 s health refresher classifies the M1 verdict after each sample (the
//! same merge `GET /health` serves) and gives it to a [`SystemEventTracker`].
//! The tracker emits:
//!
//! - `system.health_verdict` when the overall verdict (`ok`, `degraded`,
//!   `error`) changes;
//! - `system.upgrade_state` when the verdict's upgrade input changes: its
//!   state badge, `update_available`, `latest_version`, `handoff_pending` or
//!   `failed_artifact`. The check age alone is not a change.
//!
//! The first classification after start is the baseline and emits nothing:
//! a client reads `GET /health` for the current value and the events for
//! changes. Reason sentences use the redacted wording, because a GUI
//! session token can read both streams.

use super::health_verdict::{classify_with_detail, DetailAccess, HealthVerdict};
use super::sse::SseEvent;
use super::state::AppState;

/// Event type for a change of the overall M1 verdict.
pub(super) const HEALTH_VERDICT_EVENT: &str = "system.health_verdict";
/// Event type for a change of the M1 upgrade input.
pub(super) const UPGRADE_STATE_EVENT: &str = "system.upgrade_state";

/// The parts of the upgrade input whose change is an upgrade-state event.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpgradeKey {
    state: &'static str,
    update_available: Option<bool>,
    latest_version: Option<String>,
    handoff_pending: bool,
    failed_artifact: bool,
}

impl UpgradeKey {
    fn of(verdict: &HealthVerdict) -> Self {
        let upgrade = &verdict.inputs.upgrade;
        Self {
            state: upgrade.state,
            update_available: upgrade.update_available,
            latest_version: upgrade.latest_version.clone(),
            handoff_pending: upgrade.handoff_pending,
            failed_artifact: upgrade.failed_artifact,
        }
    }
}

/// The last verdict and upgrade input the refresher saw.
#[derive(Debug, Default)]
pub(super) struct SystemEventTracker {
    verdict: Option<&'static str>,
    upgrade: Option<UpgradeKey>,
}

impl SystemEventTracker {
    /// The events for `verdict` against the previous observation. The first
    /// call records a baseline and returns nothing.
    pub(super) fn observe(&mut self, verdict: &HealthVerdict, now_unix: u64) -> Vec<SseEvent> {
        let mut events = Vec::new();
        let previous = self.verdict.replace(verdict.verdict);
        if let Some(previous) = previous.filter(|previous| *previous != verdict.verdict) {
            events.push(SseEvent {
                event_type: HEALTH_VERDICT_EVENT.to_string(),
                data: serde_json::json!({
                    "verdict": verdict.verdict,
                    "previous": previous,
                    "reasons": verdict.reasons,
                    "at_unix": now_unix,
                }),
            });
        }
        let key = UpgradeKey::of(verdict);
        let previous = self.upgrade.replace(key.clone());
        if let Some(previous) = previous.filter(|previous| *previous != key) {
            events.push(SseEvent {
                event_type: UPGRADE_STATE_EVENT.to_string(),
                data: serde_json::json!({
                    "state": key.state,
                    "previous_state": previous.state,
                    "update_available": key.update_available,
                    "latest_version": key.latest_version,
                    "handoff_pending": key.handoff_pending,
                    "failed_artifact": key.failed_artifact,
                    "at_unix": now_unix,
                }),
            });
        }
        events
    }
}

/// The verdict `GET /health` would serve now, with redacted reasons.
pub(super) fn current_verdict(state: &AppState) -> HealthVerdict {
    let (peers, send_ready_peers, one_sided_peers) = state.health_snapshot.load();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let sample = state.health_snapshot.merged_verdict_inputs(
        peers,
        send_ready_peers,
        one_sided_peers,
        uptime_secs,
    );
    classify_with_detail(&sample, DetailAccess::Redacted)
}

/// Classify the current verdict and send any change on the daemon
/// broadcast, which feeds `GET /events` and `/ws`.
pub(super) fn emit_changes(state: &AppState, tracker: &mut SystemEventTracker) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    for event in tracker.observe(&current_verdict(state), now_unix) {
        // No subscriber is not an error: the event is a change notice.
        let _ = state.broadcast_tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::health_verdict::{classify, VerdictSample};

    fn healthy_sample() -> VerdictSample {
        VerdictSample {
            peers: 5,
            send_ready_peers: 5,
            uptime_secs: 3600,
            ..VerdictSample::default()
        }
    }

    /// The first observation is a baseline; an unchanged verdict emits
    /// nothing.
    #[test]
    fn baseline_and_unchanged_verdicts_emit_nothing() {
        let mut tracker = SystemEventTracker::default();
        let verdict = classify(&healthy_sample());
        assert!(tracker.observe(&verdict, 1).is_empty());
        assert!(tracker.observe(&verdict, 2).is_empty());
    }

    /// #1351: a verdict change emits exactly one `system.health_verdict`
    /// with the new and previous values.
    #[test]
    fn a_verdict_change_emits_one_health_verdict_event() {
        let mut tracker = SystemEventTracker::default();
        let healthy = classify(&healthy_sample());
        tracker.observe(&healthy, 1);
        let mut broken = healthy_sample();
        broken.identity_machine = false;
        let broken = classify(&broken);
        assert_eq!(broken.verdict, "error", "missing identity is an error");

        let events = tracker.observe(&broken, 2);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].event_type, HEALTH_VERDICT_EVENT);
        assert_eq!(events[0].data["verdict"], "error");
        assert_eq!(events[0].data["previous"], healthy.verdict);
        assert_eq!(events[0].data["at_unix"], 2);
        assert!(events[0].data["reasons"]
            .as_array()
            .is_some_and(|r| !r.is_empty()));
        assert!(tracker.observe(&broken, 3).is_empty(), "no repeat");
    }

    /// #1351: an upgrade-input change emits one `system.upgrade_state`; a
    /// changed check age alone does not.
    #[test]
    fn an_upgrade_input_change_emits_one_upgrade_state_event() {
        let mut tracker = SystemEventTracker::default();
        let mut sample = healthy_sample();
        sample.upgrade_checks_enabled = true;
        sample.upgrade_checked_age_secs = Some(10);
        tracker.observe(&classify(&sample), 1);

        sample.upgrade_checked_age_secs = Some(20);
        assert!(
            tracker.observe(&classify(&sample), 2).is_empty(),
            "check age alone is not a state change"
        );

        sample.upgrade_handoff_pending = true;
        let verdict = classify(&sample);
        let events = tracker.observe(&verdict, 3);
        let upgrade: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == UPGRADE_STATE_EVENT)
            .collect();
        assert_eq!(upgrade.len(), 1, "{events:?}");
        assert_eq!(upgrade[0].data["handoff_pending"], true);
        assert_eq!(upgrade[0].data["state"], verdict.inputs.upgrade.state);
        assert!(upgrade[0].data.get("previous_state").is_some());
    }

    /// #1351: the event reaches the daemon broadcast that `GET /events`
    /// streams (and `/ws` forwards; see the ws tests).
    #[tokio::test]
    async fn emitted_changes_reach_the_events_broadcast() {
        let (state, _dir) =
            crate::server::routes::named_groups::tests::secure_endpoint_test_state()
                .await
                .expect("test state");
        let mut events = state.broadcast_tx.subscribe();
        let mut tracker = SystemEventTracker::default();
        emit_changes(&state, &mut tracker);
        assert!(events.try_recv().is_err(), "the baseline emits nothing");

        // Force a different previous verdict, as after a change.
        tracker.verdict = Some("unseen");
        emit_changes(&state, &mut tracker);
        let event = events.try_recv().expect("one system event");
        assert_eq!(event.event_type, HEALTH_VERDICT_EVENT);
        assert_eq!(event.data["previous"], "unseen");
    }
}
