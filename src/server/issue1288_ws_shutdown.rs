//! #1288 row 4: a connected WebSocket session is a shutdown owner.
//!
//! Axum detaches the upgrade callback. The session loop and its children
//! (writer, direct, call, and keepalive forwarders, shared and per-session
//! topic forwarders) hold `AppState` or the `Agent`. They close when
//! `shutdown_notify` fires, but nothing joins them. The production close
//! grace is a few seconds and can finish during agent teardown, so an
//! unjoined session has already dropped its owners by the time
//! `shutdown_and_wait` returns. [`park_session_if_armed`] keeps that
//! cleanup on an await the shutdown drain must abort.
//!
//! The daemon binds loopback only, with no bootstrap peers, mDNS, port
//! mapping, or peer cache.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

/// Armed by [`arm_session_cleanup_hold`] for one session cleanup.
static SESSION_CLEANUP_HOLD: AtomicBool = AtomicBool::new(false);

/// The next WebSocket session cleanup should park until its task is aborted.
pub(super) fn arm_session_cleanup_hold() {
    SESSION_CLEANUP_HOLD.store(true, Ordering::SeqCst);
}

/// Parks the calling session task when a hold is armed. One-shot.
pub(super) async fn park_session_if_armed() {
    if SESSION_CLEANUP_HOLD.swap(false, Ordering::SeqCst) {
        std::future::pending::<()>().await;
    }
}

/// Per-daemon upgrade handoff hold. Keyed by the `AppState` allocation so
/// another test's socket is not parked.
pub(super) struct UpgradeHold {
    parked: AtomicUsize,
}

fn upgrade_holds() -> &'static std::sync::Mutex<Vec<(usize, Arc<UpgradeHold>)>> {
    static HOLDS: std::sync::Mutex<Vec<(usize, Arc<UpgradeHold>)>> =
        std::sync::Mutex::new(Vec::new());
    &HOLDS
}

/// The next upgrade handoffs for this daemon park before the session starts.
pub(super) fn arm_upgrade_park(state: &Arc<super::state::AppState>) -> Arc<UpgradeHold> {
    let hold = Arc::new(UpgradeHold {
        parked: AtomicUsize::new(0),
    });
    let key = Arc::as_ptr(state) as usize;
    let mut guard = upgrade_holds()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.retain(|(existing, _)| *existing != key);
    guard.push((key, Arc::clone(&hold)));
    hold
}

/// Parks a registered upgrade task for [`arm_upgrade_park`].
pub(super) async fn park_before_registration_if_armed(state: &Arc<super::state::AppState>) {
    let hold = {
        let key = Arc::as_ptr(state) as usize;
        let guard = upgrade_holds()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .iter()
            .find(|(existing, _)| *existing == key)
            .map(|(_, hold)| Arc::clone(hold))
    };
    if let Some(hold) = hold {
        hold.parked.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
    }
}

/// Per-store backfill hold. Only the armed store's query parks, so a
/// parallel unit test's history read is left alone.
pub(super) struct BackfillHold {
    released: AtomicBool,
    parked: AtomicUsize,
    drain_waiting: AtomicBool,
}

fn backfill_holds() -> &'static std::sync::Mutex<Vec<(usize, Arc<BackfillHold>)>> {
    static HOLDS: std::sync::Mutex<Vec<(usize, Arc<BackfillHold>)>> =
        std::sync::Mutex::new(Vec::new());
    &HOLDS
}

/// History backfills that clone this daemon's store park inside the blocking
/// query, while that store is still alive.
pub(super) fn arm_backfill_hold(state: &super::state::AppState) -> Option<Arc<BackfillHold>> {
    let store = state.agent.history()?.store();
    let hold = Arc::new(BackfillHold {
        released: AtomicBool::new(false),
        parked: AtomicUsize::new(0),
        drain_waiting: AtomicBool::new(false),
    });
    let key = Arc::as_ptr(store) as usize;
    let mut guard = backfill_holds()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.retain(|(existing, _)| *existing != key);
    guard.push((key, Arc::clone(&hold)));
    Some(hold)
}

/// Called on the blocking pool with the store the query is about to use.
pub(super) fn park_backfill_hold(store: &Arc<crate::history::Store>) {
    let hold = {
        let key = Arc::as_ptr(store) as usize;
        let guard = backfill_holds()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .iter()
            .find(|(existing, _)| *existing == key)
            .map(|(_, hold)| Arc::clone(hold))
    };
    if let Some(hold) = hold {
        hold.parked.fetch_add(1, Ordering::SeqCst);
        while !hold.released.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// The shutdown drain has closed backfill admission for this daemon's store
/// and is waiting on at least one read. Keyed by the store so a parallel
/// test's drain does not release this hold.
pub(super) fn mark_backfill_drain_waiting(state: &super::state::AppState) {
    let Some(history) = state.agent.history() else {
        return;
    };
    let store = history.store();
    let key = Arc::as_ptr(store) as usize;
    let guard = backfill_holds()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, hold)) = guard.iter().find(|(existing, _)| *existing == key) {
        hold.drain_waiting.store(true, Ordering::SeqCst);
    }
}

const WAIT: Duration = Duration::from_secs(20);
const LIFECYCLE: Duration = Duration::from_secs(60);

fn loopback_daemon_config(root: &std::path::Path) -> Result<super::DaemonConfig> {
    Ok(serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": format!(
            "x0x.test.1288.ws.{}.{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )
    }))?)
}

fn loopback_daemon_options() -> super::ServeOptions {
    super::ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..super::ServeOptions::default()
    }
}

struct Daemon {
    _root: tempfile::TempDir,
    config: super::DaemonConfig,
    handle: super::ServerHandle,
    state_weak: std::sync::Weak<super::state::AppState>,
    agent_weak: std::sync::Weak<crate::Agent>,
}

struct ShutdownOutcome {
    at_return: (usize, usize),
    relaunch: std::result::Result<(), String>,
}

impl std::fmt::Debug for ShutdownOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownOutcome")
            .field("at_return", &self.at_return)
            .field("relaunch", &self.relaunch)
            .finish()
    }
}

async fn start_daemon() -> Result<(Daemon, std::sync::Arc<super::state::AppState>)> {
    let root = tempfile::tempdir()?;
    let config = loopback_daemon_config(root.path())?;
    let handle = tokio::time::timeout(
        LIFECYCLE,
        super::serve_with_options(config.clone(), loopback_daemon_options()),
    )
    .await
    .context("daemon starts within 60 s")??;
    let state = handle.test_state.upgrade().context("live daemon state")?;
    let daemon = Daemon {
        _root: root,
        config,
        handle,
        state_weak: std::sync::Arc::downgrade(&state),
        agent_weak: std::sync::Arc::downgrade(&state.agent),
    };
    Ok((daemon, state))
}

impl Daemon {
    async fn stop_and_relaunch(self) -> Result<ShutdownOutcome> {
        let Daemon {
            _root,
            config,
            handle,
            state_weak,
            agent_weak,
        } = self;
        tokio::time::timeout(LIFECYCLE, handle.shutdown_and_wait())
            .await
            .context("shutdown returns within 60 s")?
            .context("shutdown")?;
        let at_return = (state_weak.strong_count(), agent_weak.strong_count());
        let relaunch = match tokio::time::timeout(
            LIFECYCLE,
            super::serve_with_options(config, loopback_daemon_options()),
        )
        .await
        {
            Err(_) => Err("the relaunch did not return within 60 s".to_string()),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Ok(Ok(relaunched)) => tokio::time::timeout(LIFECYCLE, relaunched.shutdown_and_wait())
                .await
                .map_err(|_| "the relaunched daemon did not stop within 60 s".to_string())
                .and_then(|stopped| stopped.map_err(|e| format!("{e:#}"))),
        };
        Ok(ShutdownOutcome {
            at_return,
            relaunch,
        })
    }
}

/// A subscribed client that is still connected at shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_connected_ws_session_releases_owner_at_shutdown() -> Result<()> {
    let (daemon, state) = start_daemon().await?;
    let addr = daemon.handle.local_addr();
    let token = state.api_token.clone();
    let topic = "x0x.test.1288.row4";

    let mut request = format!("ws://{addr}/ws").into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .context("authorization header")?,
    );
    let (socket, _) = tokio::time::timeout(WAIT, tokio_tungstenite::connect_async(request))
        .await
        .context("websocket upgrade timed out")?
        .context("websocket upgrade")?;
    let (mut sink, mut stream) = socket.split();

    let subscribe = serde_json::json!({ "type": "subscribe", "topics": [topic] }).to_string();
    sink.send(Message::Text(subscribe))
        .await
        .context("subscribe")?;
    let read_deadline = tokio::time::Instant::now() + WAIT;
    let mut subscribed = false;
    while tokio::time::Instant::now() < read_deadline {
        let frame = tokio::time::timeout(WAIT, stream.next())
            .await
            .context("subscribed frame timed out")?
            .context("socket closed before subscribe ack")?
            .context("socket error before subscribe ack")?;
        if frame
            .to_text()
            .unwrap_or("")
            .contains("\"type\":\"subscribed\"")
        {
            subscribed = true;
            break;
        }
    }
    anyhow::ensure!(
        subscribed,
        "the session did not acknowledge the subscription"
    );

    // Cleanup of this live session parks until the task is aborted. The
    // client stays connected across shutdown.
    arm_session_cleanup_hold();
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    drop((sink, stream));

    assert_eq!(
        outcome.at_return,
        (0, 0),
        "a connected WebSocket session must release AppState and Agent when \
         shutdown_and_wait returns (outcome: {outcome:?})"
    );
    assert!(
        outcome.relaunch.is_ok(),
        "a same-dir relaunch must succeed (outcome: {outcome:?})"
    );
    Ok(())
}

async fn connect_ws(
    addr: std::net::SocketAddr,
    token: &str,
    path: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let mut request = format!("ws://{addr}{path}").into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .context("authorization header")?,
    );
    let (socket, _) = tokio::time::timeout(WAIT, tokio_tungstenite::connect_async(request))
        .await
        .context("websocket upgrade timed out")?
        .context("websocket upgrade")?;
    Ok(socket)
}

/// Both upgrade callbacks park before the session starts. The handoff task
/// is already on the drain, so shutdown releases its AppState and the same
/// directory reopens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_ws_upgrade_parked_before_session_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon().await?;
    let addr = daemon.handle.local_addr();
    let token = state.api_token.clone();
    let hold = arm_upgrade_park(&state);
    let plain = connect_ws(addr, &token, "/ws").await?;
    let direct = connect_ws(addr, &token, "/ws/direct").await?;
    let deadline = tokio::time::Instant::now() + WAIT;
    while hold.parked.load(Ordering::SeqCst) < 2 {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the upgrade handoff did not park before the session (parked {})",
            hold.parked.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    drop((plain, direct));

    assert_eq!(
        outcome.at_return,
        (0, 0),
        "an upgrade parked before the session must release AppState and Agent \
         when shutdown_and_wait returns (outcome: {outcome:?})"
    );
    assert!(
        outcome.relaunch.is_ok(),
        "a same-dir relaunch must succeed (outcome: {outcome:?})"
    );
    Ok(())
}

/// Direct and topic backfills that finish inside the shutdown grace release
/// the history store, so the same directory reopens. The reads are released
/// when this daemon's drain starts waiting.
/// [`issue1288_ws_backfill_stalled_past_shutdown_budget_keeps_owner`] keeps
/// one read parked past that grace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_ws_backfill_parked_query_reopens_same_dir() -> Result<()> {
    let (daemon, state) = start_daemon().await?;
    let addr = daemon.handle.local_addr();
    let token = state.api_token.clone();
    let hold = arm_backfill_hold(&state).context("daemon history store")?;

    let direct = connect_ws(addr, &token, "/ws/direct?backfill=1").await?;
    let mut plain = connect_ws(addr, &token, "/ws").await?;
    let subscribe = serde_json::json!({
        "type": "subscribe",
        "topics": ["x0x.test.1288.backfill"],
        "backfill": { "limit": 1 }
    })
    .to_string();
    plain
        .send(Message::Text(subscribe))
        .await
        .context("subscribe with backfill")?;

    let deadline = tokio::time::Instant::now() + WAIT;
    while hold.parked.load(Ordering::SeqCst) < 2 {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "both history backfills did not park (parked {})",
            hold.parked.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(state);

    let shutdown = tokio::spawn(async move { daemon.stop_and_relaunch().await });
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if hold.drain_waiting.load(Ordering::SeqCst) {
            break;
        }
        if shutdown.is_finished() {
            let outcome = shutdown.await.context("shutdown task")??;
            anyhow::bail!(
                "shutdown returned while a backfill query still held the store \
                 (outcome: {outcome:?})"
            );
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the drain did not wait for the parked backfill queries"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    hold.released.store(true, Ordering::SeqCst);
    let outcome = shutdown.await.context("shutdown task")??;
    drop((direct, plain));

    assert_eq!(
        outcome.at_return,
        (0, 0),
        "a finished backfill must release AppState and Agent when \
         shutdown_and_wait returns (outcome: {outcome:?})"
    );
    assert!(
        outcome.relaunch.is_ok(),
        "a same-dir relaunch must succeed after the backfill releases the store \
         (outcome: {outcome:?})"
    );
    Ok(())
}

/// A history read that stays parked past the shutdown grace must not be
/// dropped and reported as a released owner. Shutdown returns within the
/// test bound, the result is an error, and the registry still owns the read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_ws_backfill_stalled_past_shutdown_budget_keeps_owner() -> Result<()> {
    let (daemon, state) = start_daemon().await?;
    let addr = daemon.handle.local_addr();
    let token = state.api_token.clone();
    let stats = Arc::clone(&state.ws_outbound_stats);
    let hold = arm_backfill_hold(&state).context("daemon history store")?;
    let socket = connect_ws(addr, &token, "/ws/direct?backfill=1").await?;

    let deadline = tokio::time::Instant::now() + WAIT;
    while hold.parked.load(Ordering::SeqCst) < 1 {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the history backfill did not park (parked {})",
            hold.parked.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(state);

    let Daemon {
        _root,
        config: _,
        handle,
        state_weak: _,
        agent_weak: _,
    } = daemon;
    let shutdown = tokio::time::timeout(WAIT, handle.shutdown_and_wait()).await;
    let result = match shutdown {
        Err(_) => {
            anyhow::bail!("shutdown did not return within {WAIT:?} while a backfill stayed parked")
        }
        Ok(result) => result,
    };
    assert!(
        result.is_err(),
        "a backfill still parked past the grace must not be reported as a released shutdown: {result:?}"
    );
    assert!(
        super::ws::unfinished_backfill_reads(&stats) >= 1,
        "the stalled read must stay owned after shutdown returns"
    );
    assert!(
        !hold.released.load(Ordering::SeqCst),
        "the regression must keep the read parked until after shutdown returns"
    );
    assert!(
        hold.parked.load(Ordering::SeqCst) >= 1,
        "the blocking read must still be inside the park"
    );

    hold.released.store(true, Ordering::SeqCst);
    let cleanup = tokio::time::Instant::now() + WAIT;
    while super::ws::unfinished_backfill_reads(&stats) > 0 {
        anyhow::ensure!(
            tokio::time::Instant::now() < cleanup,
            "the stalled read did not finish after it was released"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(socket);
    drop(_root);
    Ok(())
}

/// Completed backfill handles are reclaimed on the next registration.
/// A read that has not finished stays owned. No daemon is started.
#[tokio::test]
async fn issue1288_repeated_backfill_reaps_completed_reads() {
    let stats = Arc::new(super::ws::WsOutboundStats::default());
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    assert!(super::ws::track_backfill_task(&stats, async move {
        let _ = done_tx.send(());
    }));
    done_rx.await.expect("completed read signals");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if super::ws::backfill_read_registry_len(&stats) == 1
            && super::ws::unfinished_backfill_reads(&stats) == 0
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the completed backfill was not observed finished"
        );
        tokio::task::yield_now().await;
    }

    let (park_tx, park_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(super::ws::track_backfill_task(&stats, async move {
        let _ = park_rx.await;
    }));
    assert_eq!(
        super::ws::backfill_read_registry_len(&stats),
        1,
        "the completed handle must be reclaimed when the next read is registered"
    );
    assert_eq!(
        super::ws::unfinished_backfill_reads(&stats),
        1,
        "the pending read must stay owned"
    );
    let _ = park_tx.send(());
}
