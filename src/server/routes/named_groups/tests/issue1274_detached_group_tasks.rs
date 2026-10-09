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

/// Same shape, found by the #1274 audit: an ADR 0107 join-artifact egress
/// task holds the AppState up to its artifact deadline. A secure share to
/// an unavailable member retries for up to `PENDING_JOIN_RESULT_TTL`
/// (10 min). The body here stands in for that retry loop: it holds what a
/// secure-share body captures (the AppState) and waits. The task goes
/// through the real `spawn_join_artifact_egress` and its registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1274_join_artifact_egress_at_shutdown_releases_owner() -> Result<()> {
    let (daemon, state) = start_daemon("egress").await?;
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let body_state = Arc::clone(&state);
    spawn_join_artifact_egress(
        &state,
        &random_hex(32),
        &random_hex(32),
        "secure_share",
        Instant::now() + PENDING_JOIN_RESULT_TTL,
        async move {
            let _held = body_state;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        },
    );
    tokio::time::timeout(WAIT, started_rx)
        .await
        .context("the egress body starts")??;
    drop(state);

    let outcome = daemon.stop_and_relaunch().await?;
    assert_released(&outcome, "join-artifact egress");
    Ok(())
}

/// Once the shutdown drain has started, a new join-artifact egress is
/// refused before anything is spawned (review r2, P2): the call itself
/// drops the body and keeps no AppState handle of its own, so nothing a
/// refused egress captured can outlive the call. An egress that was spawned
/// and then aborted would still own its captures until the runtime ran the
/// cancellation, after the drain may already have reported the egress
/// registry idle. The checks run at once, with no await between the call
/// and them; on this current-thread runtime no other task can run in
/// between. Inert: no daemon, no socket.
#[tokio::test]
async fn issue1274_join_artifact_egress_refused_after_shutdown_start_releases_at_once() -> Result<()>
{
    let (state, _dir) = secure_endpoint_test_state().await?;
    state.shutdown_started.cancel();
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // What a real egress body captures (the AppState), plus a probe that
    // only the body owns.
    let probe = Arc::new(());
    let probe_weak = Arc::downgrade(&probe);
    let body_ran = Arc::clone(&ran);
    let body_state = Arc::clone(&state);
    let owners_with_body = Arc::strong_count(&state);
    spawn_join_artifact_egress(
        &state,
        &random_hex(32),
        &random_hex(32),
        "secure_share",
        Instant::now() + PENDING_JOIN_RESULT_TTL,
        async move {
            let _probe = probe;
            let _held = body_state;
            body_ran.store(true, std::sync::atomic::Ordering::SeqCst);
        },
    );
    let probe_owners = probe_weak.strong_count();
    let state_owners = Arc::strong_count(&state);
    let registered = state
        .join_artifact_egress
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .flatten()
        .count();
    let ran = ran.load(std::sync::atomic::Ordering::SeqCst);
    // Expected: the body's probe has no owner, the AppState lost the body's
    // handle and gained none, nothing is registered and the body never ran.
    assert_eq!(
        (
            probe_owners,
            state_owners as i64 - owners_with_body as i64,
            registered,
            ran
        ),
        (0, -1, 0, false),
        "a refused egress must release what it captured within the call \
         (probe owners, AppState owner delta, registered, body ran)"
    );
    Ok(())
}

/// Review r3 (P2): the drain's egress fence must hold until an egress task
/// has released every owner it captured, not merely until it has left the
/// registry. A finished egress task's cleanup guard removes its own handle
/// from the registry and releases the registry lock, and only then drops
/// its `state: Arc<AppState>` field. The test parks the guard exactly
/// there (`egress_cleanup_test_seam`, which blocks that worker thread) and
/// checks, with a synchronous single poll rather than timing, that the
/// drain's idle wait is not satisfied while the guard still owns the
/// AppState, and that it is satisfied once the guard is released. Inert:
/// no daemon, no socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue1274_egress_fence_holds_until_the_cleanup_releases_its_owner() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let group = random_hex(32);
    let recipient = random_hex(32);
    let pause = egress_cleanup_test_seam::arm(&group, &recipient);
    spawn_join_artifact_egress(
        &state,
        &group,
        &recipient,
        "join_result",
        Instant::now() + PENDING_JOIN_RESULT_TTL,
        async {},
    );
    let deadline = tokio::time::Instant::now() + WAIT;
    while !pause.reached() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "the egress cleanup did not reach its pause within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // Parked: the task has left the registry, but its guard still owns the
    // AppState.
    let listed = state
        .join_artifact_egress
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(group.clone(), recipient.clone()))
        .map_or(0, Vec::len);
    let idle_while_parked =
        futures::FutureExt::now_or_never(join_artifact_egress_idle(&state)).is_some();
    pause.release();
    let idle_after_release = tokio::time::timeout(WAIT, join_artifact_egress_idle(&state))
        .await
        .is_ok();
    assert_eq!(
        (listed, idle_while_parked, idle_after_release),
        (0, false, true),
        "(registry entries while the guard is parked, drain idle while parked, drain idle \
         after release): the drain must not see the egress idle while its cleanup guard \
         still owns the AppState"
    );
    Ok(())
}
