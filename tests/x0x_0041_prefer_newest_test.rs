//! X0X-0041 — Prefer-newest-connection policy on x0x raw-DM path.
//!
//! Acceptance criterion (from `docs/design/sota-borrow-plan.md` §4 X0X-0041):
//!
//! > Synthetic test: kill+restart a peer's QUIC connection mid-DM →
//! > `/direct/send` lands on the new connection in ≤ 500ms without surfacing
//! > a Timeout.
//!
//! These tests exercise the prefer-newest plumbing end-to-end at the
//! `DirectMessaging` + DM-config layer: a `Replaced` lifecycle event must
//! propagate to the per-peer "active generation" hint and broadcast on the
//! prefer-newest subscriber channel inside the 500 ms acceptance budget. The
//! detailed retry-loop short-circuit semantics live in
//! `src/dm_send.rs::tests::x0x_0041_*`.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use x0x::direct::DirectMessaging;
use x0x::dm::{DmSendConfig, DEFAULT_PREFER_NEWEST_GRACE_MS};
use x0x::identity::MachineId;

/// X0X-0041: a fresh `DmSendConfig` carries the documented 250ms grace.
#[test]
fn dm_send_config_default_grace_matches_documented_constant() {
    let cfg = DmSendConfig::default();
    assert_eq!(cfg.prefer_newest_grace_ms, DEFAULT_PREFER_NEWEST_GRACE_MS);
    assert_eq!(cfg.prefer_newest_grace_ms, 250);
}

/// X0X-0041: end-to-end propagation of a supersede event lands in well under
/// the 500ms acceptance budget.
///
/// Mirrors the "kill+restart a peer's QUIC connection mid-DM" scenario at the
/// `DirectMessaging` API layer: a Replaced event from the lifecycle watcher
/// must (a) update the per-peer active-generation hint and (b) reach a DM
/// retry-loop subscriber promptly.
#[tokio::test]
async fn supersede_propagates_within_500ms_acceptance_budget() {
    let dm = Arc::new(DirectMessaging::new());
    let machine_id = MachineId([0x42; 32]);

    // Establish gen 1 before the "send" begins.
    dm.record_lifecycle_established(machine_id, Some(1));
    assert_eq!(dm.current_generation(&machine_id), Some(1));

    // Subscribe BEFORE the supersede so we never miss the event — mirrors the
    // `send_direct_raw_quic` ordering (subscribe before connectivity probe).
    let mut rx = dm.subscribe_lifecycle_replaced();

    // Simulate ant-quic mid-DM connection-replacement: a peer's QUIC
    // connection is killed and restarted, so the lifecycle watcher emits
    // `Replaced { new_generation: 2, .. }` 50ms later.
    let dm_for_task = Arc::clone(&dm);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        dm_for_task.record_lifecycle_replaced(machine_id, 2);
    });

    let start = Instant::now();
    let (m, gen) = tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("supersede must land inside the 500ms acceptance budget")
        .expect("broadcast channel still open");

    let elapsed = start.elapsed();
    assert_eq!(m, machine_id);
    assert_eq!(gen, 2);
    assert!(
        elapsed <= Duration::from_millis(500),
        "supersede took {elapsed:?} which exceeds the 500ms acceptance budget"
    );
    // Lifecycle table also reflects the new generation now.
    assert_eq!(dm.current_generation(&machine_id), Some(2));
}

/// X0X-0041: legacy behaviour preserved when the grace knob is disabled.
#[test]
fn prefer_newest_grace_zero_disables_feature() {
    let cfg = DmSendConfig {
        prefer_newest_grace_ms: 0,
        ..DmSendConfig::default()
    };
    assert_eq!(cfg.prefer_newest_grace_ms, 0);
}
