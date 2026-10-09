//! #1288 row 4: a connected WebSocket session is a shutdown owner.
//!
//! Axum detaches the upgrade callback. The session loop and its children
//! (writer, direct, call, and keepalive forwarders, shared and per-session
//! topic forwarders) hold `AppState` or the `Agent` and used to outlive
//! `shutdown_and_wait`. This test subscribes one client and leaves it
//! connected, with the reader stalled so the writer's socket send is still
//! in flight at shutdown. The AppState and Agent strong counts must be 0
//! when `shutdown_and_wait` returns, and a same-dir relaunch must succeed.
//!
//! The daemon binds loopback only, with no bootstrap peers, mDNS, port
//! mapping, or peer cache.

use std::time::Duration;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

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

fn shrink_recv_buffer(stream: &std::net::TcpStream) -> Result<()> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(stream);
    let size: libc::c_int = 1024;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if rc != 0 {
        anyhow::bail!(
            "setsockopt SO_RCVBUF failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

async fn outbound_dropped(addr: std::net::SocketAddr, token: &str) -> Result<u64> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/diagnostics/ws"))
        .bearer_auth(token)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .context("GET /diagnostics/ws")?
        .error_for_status()
        .context("diagnostics status")?
        .json()
        .await
        .context("diagnostics json")?;
    body.get("ws_outbound_dropped")
        .and_then(|value| value.as_u64())
        .context("ws_outbound_dropped missing")
}

/// A subscribed client that is still connected, and not reading, at shutdown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_connected_ws_session_releases_owner_at_shutdown() -> Result<()> {
    let (daemon, state) = start_daemon().await?;
    let addr = daemon.handle.local_addr();
    let token = state.api_token.clone();
    let topic = "x0x.test.1288.row4";

    let std_stream = std::net::TcpStream::connect(addr).context("tcp connect")?;
    std_stream.set_nodelay(true)?;
    shrink_recv_buffer(&std_stream)?;
    std_stream.set_nonblocking(true)?;
    let tcp = tokio::net::TcpStream::from_std(std_stream).context("tokio tcp")?;

    let mut request = format!("ws://{addr}/ws").into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .context("authorization header")?,
    );
    let (socket, _) = tokio::time::timeout(WAIT, tokio_tungstenite::client_async(request, tcp))
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

    // Stall the reader. Pings are answered with pongs; once the tiny receive
    // window and the server send buffer are full, the writer blocks in
    // `send` and the session's close grace still holds AppState.
    let ping = r#"{"type":"ping"}"#.to_string();
    let flood_deadline = tokio::time::Instant::now() + WAIT;
    let mut dropped = 0u64;
    let mut sent = 0u32;
    while dropped == 0 && sent < 100_000 && tokio::time::Instant::now() < flood_deadline {
        for _ in 0..200 {
            tokio::time::timeout(
                Duration::from_secs(2),
                sink.send(Message::Text(ping.clone())),
            )
            .await
            .context("ping send timed out; the client is still connected")?
            .context("ping send")?;
            sent += 1;
        }
        dropped = outbound_dropped(addr, &token).await?;
    }
    anyhow::ensure!(
        dropped > 0,
        "the stalled client never filled the outbound queue (sent {sent} pings); the writer was not in flight"
    );
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    // Keep the client connected until shutdown has returned.
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
