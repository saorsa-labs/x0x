//! #1288 row 1: the public-group bootstrap outbox step holds this daemon's
//! AppState across a network send and across the outbox writes on either
//! side of that send.
//!
//! Two owners run the step. A SignedPublic member add fires
//! `spawn_public_group_bootstrap_delivery`, and the `bg_tasks` timer runs
//! the same step every 500 ms. The send waits for a v2 application ACK. The
//! timer is aborted after the shutdown grace, so a write parked between the
//! synced temp file and the rename can be cut.
//!
//! Each test starts a loopback daemon, holds that in-flight state at
//! shutdown, and checks the #1274 bar: AppState and Agent strong counts are
//! 0 when `shutdown_and_wait` returns, and an immediate same-dir relaunch
//! succeeds. The write test also checks that the parked outbox write
//! finishes with a valid sidecar and no temp file left beside it.
//!
//! The daemons bind loopback only (`127.0.0.1:0`) with no bootstrap peers,
//! mDNS, port mapping or peer cache; no test traffic leaves the process.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;

use super::super::{
    add_named_group_member, create_named_group, AddNamedGroupMemberRequest, CreateGroupRequest,
};
use super::issue1269_shutdown_apply_boundary::leftover_temp_files;
use super::*;

/// How long a test waits for a send or a write to park.
const WAIT: Duration = Duration::from_secs(15);
/// Bound on one daemon start or shutdown.
const LIFECYCLE: Duration = Duration::from_secs(60);
/// After `shutdown_started` fires (the drain's first act, before the 2 s
/// grace), this wait is past that grace and inside the 10 s shielded-apply
/// bound. An abortable outbox write has already been cut. A shielded one is
/// still waited on, so releasing the pause lets it finish before shutdown
/// returns.
const PAST_ABORT_GRACE: Duration = Duration::from_secs(4);

fn loopback_daemon_config(
    root: &std::path::Path,
    tag: &str,
) -> Result<crate::server::DaemonConfig> {
    Ok(serde_json::from_value(serde_json::json!({
        "bind_address": "127.0.0.1:0",
        "api_address": "127.0.0.1:0",
        "data_dir": root.join("data"),
        "identity_dir": root.join("identity"),
        "bootstrap_peers": [],
        "mdns_enabled": false,
        "port_mapping_enabled": false,
        "network_id": format!(
            "x0x.test.1288.{tag}.{}.{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )
    }))?)
}

fn loopback_daemon_options() -> crate::server::ServeOptions {
    crate::server::ServeOptions {
        skip_update_check: true,
        cli_no_port_mapping: true,
        cli_disable_peer_cache: true,
        self_update_enabled: false,
        ..crate::server::ServeOptions::default()
    }
}

/// A running loopback daemon and weak handles to what its shutdown must
/// release.
struct Daemon {
    _root: tempfile::TempDir,
    config: crate::server::DaemonConfig,
    handle: crate::server::ServerHandle,
    state_weak: std::sync::Weak<AppState>,
    agent_weak: std::sync::Weak<x0x::Agent>,
}

/// What a shutdown left behind.
struct ShutdownOutcome {
    /// Strong counts of the AppState and the Agent when `shutdown_and_wait`
    /// returned.
    at_return: (usize, usize),
    /// The same-dir relaunch, attempted at once.
    relaunch: std::result::Result<(), String>,
    /// Kept so a test can read the sidecar after the relaunch. Dropping it
    /// removes the data directory.
    _root: tempfile::TempDir,
}

async fn start_daemon(tag: &str) -> Result<(Daemon, Arc<AppState>)> {
    let root = tempfile::tempdir()?;
    let config = loopback_daemon_config(root.path(), tag)?;
    let handle = tokio::time::timeout(
        LIFECYCLE,
        crate::server::serve_with_options(config.clone(), loopback_daemon_options()),
    )
    .await
    .context("daemon starts within 60 s")??;
    let state = handle.test_state.upgrade().context("live daemon state")?;
    let daemon = Daemon {
        _root: root,
        config,
        handle,
        state_weak: Arc::downgrade(&state),
        agent_weak: Arc::downgrade(&state.agent),
    };
    Ok((daemon, state))
}

impl Daemon {
    /// Shut the daemon down, read both strong counts as soon as
    /// `shutdown_and_wait` returns, and relaunch on the same directories at
    /// once. The caller must have dropped its own AppState handles.
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
            crate::server::serve_with_options(config, loopback_daemon_options()),
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
            _root,
        })
    }
}

fn assert_released(outcome: &ShutdownOutcome, path: &str) {
    assert_eq!(
        outcome.at_return,
        (0, 0),
        "{path}: the AppState and Agent strong counts must be 0 when shutdown_and_wait \
         returns (counts {:?}, relaunch {:?})",
        outcome.at_return,
        outcome.relaunch
    );
    assert!(
        outcome.relaunch.is_ok(),
        "{path}: a same-dir relaunch must succeed (relaunch {:?})",
        outcome.relaunch
    );
}

fn owner() -> axum::extract::Extension<crate::server::rider_auth::ActorContext> {
    axum::extract::Extension(crate::server::rider_auth::ActorContext::Owner { durable: true })
}

fn random_hex(bytes: usize) -> String {
    let raw: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    hex::encode(raw)
}

async fn create_public_group(state: &Arc<AppState>) -> Result<String> {
    let response = create_named_group(
        State(Arc::clone(state)),
        Json(CreateGroupRequest {
            name: "bootstrap-outbox".to_string(),
            description: String::new(),
            display_name: None,
            preset: Some("public_open".to_string()),
            policy: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a public_open group must be created: {body}"
    );
    Ok(body["group_id"]
        .as_str()
        .context("create response group_id")?
        .to_string())
}

async fn add_public_member(state: &Arc<AppState>, group_id: &str, member_hex: &str) -> Result<()> {
    let response = add_named_group_member(
        State(Arc::clone(state)),
        owner(),
        Path(group_id.to_string()),
        Json(AddNamedGroupMemberRequest {
            agent_id: member_hex.to_string(),
            display_name: None,
            treekem_key_package_b64: None,
        }),
    )
    .await
    .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "adding a SignedPublic member must enqueue its bootstrap obligation: {body}"
    );
    Ok(())
}

async fn stable_group_id(state: &AppState, group_id: &str) -> Result<String> {
    let groups = state.named_groups.read().await;
    Ok(groups
        .get(group_id)
        .context("created group is in the roster")?
        .stable_group_id()
        .to_string())
}

async fn wait_parked(reached: impl Fn() -> bool, what: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !reached() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "{what} did not park within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// A SignedPublic member add whose bootstrap delivery is parked in its send
/// at shutdown must not keep the AppState or the Agent alive, and a same-dir
/// relaunch must succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_signed_public_add_parked_in_bootstrap_send_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon("send").await?;
    let group_id = create_public_group(&state).await?;
    let stable = stable_group_id(&state, &group_id).await?;
    let member_hex = random_hex(32);
    let pause = detached_send_test_seam::arm(&detached_send_test_seam::public_bootstrap_key(
        &stable,
        &member_hex,
    ));
    add_public_member(&state, &group_id, &member_hex).await?;
    wait_parked(|| pause.reached(), "the bootstrap delivery send").await?;
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    assert_released(&outcome, "parked bootstrap send");
    Ok(())
}

/// A bootstrap-outbox write parked between the synced temp file and the
/// rename must finish across shutdown: the sidecar is valid JSON, the
/// reconciled contents are what landed, and no temp file remains.
///
/// The debt is memory-only and owed to an agent who is not a member. The
/// timer's next pass drops it and persists that. No roster save shares this
/// write, and the durability-confirmation flag is left alone: a durable
/// roster save clears that flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1288_bootstrap_outbox_write_parked_before_rename_completes() -> Result<()> {
    let (daemon, state) = start_daemon("write").await?;
    let group_id = create_public_group(&state).await?;
    let path = state.public_group_bootstrap_outbox_path.clone();
    let pause = atomic_write_test_seam::arm(&path);
    let recipient = x0x::identity::AgentId(rand::random());
    let recipient_hex = hex::encode(recipient.as_bytes());
    {
        // The live roster does not list this recipient, so the next pass
        // drops the debt and writes that. `prepare` only needs a group the
        // reconciler can find; a freshly created public group has no sealed
        // commit yet, and the drop path does not require one.
        let group = state
            .named_groups
            .read()
            .await
            .get(&group_id)
            .context("created group is in the roster")?
            .clone();
        let obligation = crate::server::routes::public_group_bootstrap_outbox::prepare_public_group_bootstrap_obligation(
            recipient,
            group,
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        state
            .public_group_bootstrap_outbox
            .write()
            .await
            .insert(obligation.key.clone(), obligation);
    }
    wait_parked(
        || pause.reached(),
        "the bootstrap outbox reconciliation write",
    )
    .await?;
    let shutdown_started = state.shutdown_started.clone();
    drop(state);

    let shutdown = tokio::spawn(async move { daemon.stop_and_relaunch().await });
    tokio::time::timeout(LIFECYCLE, shutdown_started.cancelled())
        .await
        .context("the drain cancels shutdown_started")?;
    tokio::time::sleep(PAST_ABORT_GRACE).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must still be waiting on the parked outbox write"
    );
    pause.release();
    let outcome = tokio::time::timeout(LIFECYCLE, shutdown)
        .await
        .context("shutdown task")?
        .context("shutdown task join")??;
    assert_released(&outcome, "parked bootstrap outbox write");
    assert_eq!(
        leftover_temp_files(&path),
        Vec::<String>::new(),
        "the outbox write must not leave a temp sidecar"
    );
    let sidecar = std::fs::read_to_string(&path).context("read bootstrap outbox sidecar")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&sidecar).context("bootstrap outbox sidecar is valid JSON")?;
    assert!(
        parsed.get("entries").is_some(),
        "the sidecar keeps its shape: {sidecar}"
    );
    assert!(
        !sidecar.contains(&recipient_hex),
        "reconciliation must persist the dropped obligation: {sidecar}"
    );
    Ok(())
}
