//! #1274: three background group sends were bare `tokio::spawn`s that held
//! the Agent or the daemon's AppState with no shutdown owner:
//!
//! - the public-message fan-out race (its gossip publish and its per-member
//!   unicasts);
//! - the one-shot predecessor-relay offer that a join request falls back to
//!   when its durable offer obligation cannot be persisted;
//! - the member-keyed KeyPackage catch-up request that a removal fires when
//!   the member's KeyPackage is missing.
//!
//! A send held up by back-pressure or an unavailable peer then kept the
//! Agent, and its exclusive `history.db` connection, alive after
//! `shutdown_and_wait` returned, and a same-dir relaunch in the same process
//! (the embedder path, ADR 0057) was refused. Each test drives the real
//! path on a real daemon, parks the send right before it reaches the
//! transport (`detached_send_test_seam`), shuts the daemon down while the
//! send is parked, and checks that the daemon's AppState and Agent are gone
//! when `shutdown_and_wait` returns and that a relaunch on the same
//! directories succeeds.
//!
//! The daemons bind loopback only (`127.0.0.1:0`) with no bootstrap peers,
//! mDNS, port mapping or peer cache; no test traffic leaves the process.

use super::*;

/// How long a test waits for a send to park.
const WAIT: Duration = Duration::from_secs(15);
/// Bound on one daemon start or shutdown.
const LIFECYCLE: Duration = Duration::from_secs(60);

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
            "x0x.test.1274.{tag}.{}.{:08x}",
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
#[derive(Debug)]
struct ShutdownOutcome {
    /// Strong counts of the AppState and the Agent when `shutdown_and_wait`
    /// returned.
    at_return: (usize, usize),
    /// The same-dir relaunch, attempted at once.
    relaunch: std::result::Result<(), String>,
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
        })
    }
}

fn assert_released(outcome: &ShutdownOutcome, path: &str) {
    assert_eq!(
        outcome.at_return,
        (0, 0),
        "{path}: the AppState and Agent strong counts must be 0 when shutdown_and_wait \
         returns (outcome: {outcome:?})"
    );
    assert!(
        outcome.relaunch.is_ok(),
        "{path}: a same-dir relaunch must succeed (outcome: {outcome:?})"
    );
}

async fn wait_parked(pause: &detached_send_test_seam::ArmedSendPause, what: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !pause.reached() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "{what} did not reach its send within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let raw: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
    hex::encode(raw)
}

/// Fan-out: a successful public send (HTTP 200) whose gossip race and
/// unicast to a member are both still in progress when the daemon stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1274_public_send_in_progress_at_shutdown_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon("fanout").await?;
    let group_id = insert_local_public_group(state.as_ref(), &random_hex(16)).await;
    let local_hex = hex::encode(state.agent.agent_id().as_bytes());
    let member_hex = random_hex(32);
    let stable = {
        let mut groups = state.named_groups.write().await;
        let info = groups.get_mut(&group_id).context("public group fixture")?;
        info.add_member(
            member_hex.clone(),
            x0x::groups::GroupRole::Member,
            Some(local_hex),
            None,
        );
        info.stable_group_id().to_string()
    };
    let topic = x0x::groups::public_topic_for(&stable);
    let gossip = detached_send_test_seam::arm(&detached_send_test_seam::public_gossip_key(&topic));
    let unicast = detached_send_test_seam::arm(&detached_send_test_seam::public_unicast_key(
        &stable,
        &member_hex,
    ));

    let (status, body) =
        post_group_send(Arc::clone(&state), &group_id, "issue1274 send in flight").await?;
    assert_eq!(status, StatusCode::OK, "the public send succeeds: {body}");
    wait_parked(&gossip, "the fan-out gossip race").await?;
    wait_parked(&unicast, "the fan-out unicast").await?;
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    assert_released(&outcome, "public send fan-out");
    drop((gossip, unicast));
    Ok(())
}

/// Predecessor relay: a join request whose durable offer obligation cannot
/// be persisted falls back to a one-shot offer to the authority. That send
/// is still in progress when the daemon stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1274_predecessor_relay_fallback_at_shutdown_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon("relay").await?;
    let authority = x0x::identity::AgentKeypair::generate()?.agent_id();
    let authority_hex = hex::encode(authority.as_bytes());
    let info = x0x::groups::GroupInfo::with_policy(
        "issue1274 relay".to_string(),
        String::new(),
        authority,
        random_hex(16),
        x0x::groups::GroupPolicyPreset::PublicRequestSecure.to_policy(),
    );
    let group_id = info.mls_group_id.clone();
    let stable = info.stable_group_id().to_string();
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    // The offer outbox cannot be written: its path is a (non-empty)
    // directory, so the atomic replace fails and the handler falls back.
    let outbox_path = state.requester_offer_outbox_path.clone();
    std::fs::create_dir_all(outbox_path.join("blocked"))?;
    let fallback = detached_send_test_seam::arm(
        &detached_send_test_seam::predecessor_fallback_key(&stable, &authority_hex),
    );

    let response = create_join_request(State(Arc::clone(&state)), Path(group_id.clone()), None)
        .await
        .into_response();
    let (status, body) = response_json(response).await?;
    assert_eq!(status, StatusCode::CREATED, "the join request: {body}");
    assert!(
        crate::server::routes::named_groups::requester_offer::requester_offer_snapshot(&state)
            .await
            .is_empty(),
        "the durable offer obligation was not persisted, so the one-shot fallback runs"
    );
    wait_parked(&fallback, "the predecessor-relay fallback").await?;
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    assert_released(&outcome, "predecessor-relay fallback");
    drop(fallback);
    Ok(())
}

/// Key-package catch-up: a removal finds no KeyPackage for the member,
/// answers 424 and fires the member-keyed catch-up. Its request is still in
/// progress when the daemon stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1274_key_package_catchup_at_shutdown_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon("kp").await?;
    let local = state.agent.agent_id();
    let local_hex = hex::encode(local.as_bytes());
    let group_id = random_hex(32);
    let stable = random_hex(32);
    let member_hex = random_hex(32);
    let mut info = treekem_metadata_group_info(local, &group_id, &stable);
    info.add_member(
        member_hex.clone(),
        x0x::groups::GroupRole::Member,
        Some(local_hex),
        None,
    );
    state
        .named_groups
        .write()
        .await
        .insert(group_id.clone(), info);
    let catchup = detached_send_test_seam::arm(&detached_send_test_seam::key_package_catchup_key(
        &group_id,
        &member_hex,
    ));

    let resolved = resolve_member_treekem_kp_for_removal(&state, &group_id, &member_hex).await;
    let (status, body) = match resolved {
        Ok(kp) => anyhow::bail!("the member has no KeyPackage, yet one resolved: {kp}"),
        Err(pending) => pending,
    };
    assert_eq!(status, StatusCode::FAILED_DEPENDENCY);
    assert_eq!(body["error"], "member_key_package_pending");
    wait_parked(&catchup, "the KeyPackage catch-up").await?;
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    assert_released(&outcome, "KeyPackage catch-up");
    drop(catchup);
    Ok(())
}
