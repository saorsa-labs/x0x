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

use std::sync::atomic::{AtomicBool, Ordering};
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
