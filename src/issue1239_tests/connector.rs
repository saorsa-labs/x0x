#![cfg(test)]

//! The ordinary connector must not run synchronous evidence reads on Tokio.
//! Fixtures use no sockets; the populated fixture uses only SimFabric.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

// The watchdog releases a real store writer even on the broken baseline,
// where a synchronous read freezes the sole Tokio thread and its timers.
// The test records whether its async deadline ran BEFORE that release.
async fn held_connector_read(stage: &str) {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    assert!(agent.network.is_none());
    let _permits: Vec<_> = if stage == "point_of_use" {
        (0..16)
            .map(|_| {
                agent
                    .peer_evidence()
                    .wire_limits
                    .try_lookup_permit()
                    .unwrap()
            })
            .collect()
    } else {
        Vec::new()
    };
    let (hold, hold_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let entered = Arc::new(tokio::sync::Notify::new());
    let held_now = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&entered);
    let active = Arc::clone(&held_now);
    let writer = std::thread::spawn(move || {
        if hold_rx.recv().is_ok() {
            let held = store.hold_state_for_testing();
            active.store(true, Ordering::SeqCst);
            signal.notify_one();
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            active.store(false, Ordering::SeqCst);
            drop(held);
        }
    });
    if stage == "post_dial" {
        assert!(agent
            .peer_evidence()
            .evidence_dial
            .set(Arc::new(move |_| {
                let hold = hold.clone();
                let entered = Arc::clone(&entered);
                Box::pin(async move {
                    hold.send(()).unwrap();
                    entered.notified().await;
                })
            }))
            .is_ok());
    } else {
        hold.send(()).unwrap();
        entered.notified().await;
    }

    let result = tokio::time::timeout(
        Duration::from_millis(100),
        agent.connect_to_agent(&recipient),
    )
    .await;
    let ended_while_held = held_now.load(Ordering::SeqCst);
    // Release and join BEFORE assertions, including on current main.
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
    assert!(
        result.is_err() && ended_while_held,
        "{stage}: connector blocked the current-thread timer until store release: {result:?}, held={ended_while_held}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn held_lookup_store_keeps_connector_cancellable() {
    held_connector_read("lookup").await;
}

#[tokio::test(flavor = "current_thread")]
async fn held_point_of_use_store_keeps_connector_cancellable() {
    held_connector_read("point_of_use").await;
}

#[tokio::test(flavor = "current_thread")]
async fn held_post_dial_store_keeps_connector_cancellable() {
    held_connector_read("post_dial").await;
}

#[tokio::test(flavor = "current_thread")]
async fn load_and_lookup_share_connector_budget_and_keep_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let mut agent = agent_in(dir.path()).await.unwrap();
    let (_store, ready) = install_evidence(&mut agent, dir.path()).unwrap();
    let recipient = identity::AgentId([0x39; 32]);
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    assert!(agent
        .peer_evidence()
        .lookup_responder
        .set(Arc::new(move |_| {
            let signal = Arc::clone(&signal);
            Box::pin(async move {
                signal.notify_one();
                std::future::pending::<()>().await;
            })
        }))
        .is_ok());
    tokio::time::pause();
    let deadline = tokio::time::Instant::now() + dm::dm_attempt_timeout(None);
    let mut connect = Box::pin(agent.connect_to_agent(&recipient));
    assert!(futures::poll!(&mut connect).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    ready.cancel();
    tokio::time::resume();
    tokio::select! {
        _ = entered.notified() => {},
        result = &mut connect => panic!("connector did not enter Lookup: {result:?}"),
    }
    tokio::time::pause();
    tokio::time::advance(
        deadline.saturating_duration_since(tokio::time::Instant::now()) + Duration::from_millis(1),
    )
    .await;
    let result = futures::poll!(&mut connect);
    drop(connect);
    tokio::time::resume();
    agent.try_shutdown().await.unwrap();
    assert!(
        matches!(result, Poll::Ready(Ok(connectivity::ConnectOutcome::NotFound))),
        "Lookup restarted or escaped the evidence budget instead of the existing NotFound fallback: {result:?}"
    );
    assert_eq!(
        agent
            .direct_messaging
            .diagnostics_snapshot()
            .stats
            .outgoing_send_failed,
        0
    );
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn briefly_held_store_preserves_connector_evidence_and_dial() {
    let dir = tempfile::tempdir().unwrap();
    let (agent, recipient, store, _inbox, _fabric) = gossip_fixture(dir.path()).await.unwrap();
    let dialled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dialled);
    assert!(agent
        .peer_evidence()
        .evidence_dial
        .set(Arc::new(move |_| {
            observed.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }))
        .is_ok());
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&entered);
    let (release, release_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let _held = store.hold_state_for_testing();
        signal.notify_one();
        // Release independently of Tokio, so the control also terminates
        // on the blocking baseline. An immediate try-lock refusal loses
        // the usable evidence and fails the dial assertion below.
        let _ = release_rx.recv_timeout(Duration::from_millis(50));
    });
    entered.notified().await;
    let result = agent.connect_to_agent(&recipient).await;
    let _ = release.send(());
    writer.join().unwrap();
    agent.try_shutdown().await.unwrap();
    assert!(matches!(
        result,
        Ok(connectivity::ConnectOutcome::Unreachable)
    ));
    assert!(dialled.load(Ordering::SeqCst));
    assert_eq!(Arc::strong_count(agent.peer_evidence()), 1);
}
