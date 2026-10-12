//! #1275: the server's listeners apply named-group events that persist
//! roster and TreeKEM state. The shutdown drain (`drain_server_tasks`)
//! gives a listener a 2 s grace and then aborts it, so an apply that ran
//! inline in the listener could be cut off in the middle of its atomic
//! named-groups write: a synced temp file is left behind and the on-disk
//! state lags memory. Each test drives a real listener, parks the apply's
//! write after its temp file is synced and before the rename (the #1269
//! write pause), stops the daemon's tasks while the write is parked, and
//! then checks what is on disk.

use super::issue1269_shutdown_apply_boundary::{leftover_temp_files, persisted_has, wait_reached};
use super::*;

/// How long a test waits for a parked write, a delivery or a drain.
const WAIT: Duration = Duration::from_secs(15);
const GROUP: &str = "1275-listener-local-key";
const STABLE: &str = "1275-listener-stable-id";
/// The group name the listener's apply writes.
const RENAMED: &str = "1275 renamed by a listener apply";

/// What a stop that began while a listener's write was parked left behind.
#[derive(Debug)]
pub(in crate::server) struct StopOutcome {
    /// The drain was still running after the 2 s grace: it waited for the
    /// apply instead of aborting it.
    pub(in crate::server) drain_waited: bool,
    /// The persisted named-groups file holds the applied state.
    pub(in crate::server) persisted: bool,
    /// Temp files of an unfinished atomic write next to that file.
    pub(in crate::server) temp_files: Vec<String>,
}

impl StopOutcome {
    /// The apply ran to completion: the drain waited for it, the write
    /// reached its rename and left no temp file.
    pub(in crate::server) fn apply_completed(&self) -> bool {
        self.drain_waited && self.persisted && self.temp_files.is_empty()
    }
}

/// Run the shutdown drain over `bg_tasks` (and the AppState registries)
/// while the write armed by `pause` is parked. Past the 2 s grace, release
/// the write, let the drain end, and report what is on disk at `path`.
pub(in crate::server) async fn stop_while_write_parked(
    state: &Arc<AppState>,
    bg_tasks: Vec<tokio::task::JoinHandle<()>>,
    pause: &atomic_write_test_seam::WritePause,
    path: &FsPath,
    applied_marker: &str,
) -> Result<StopOutcome> {
    let drain_state = Arc::clone(state);
    let drain = tokio::spawn(async move {
        crate::server::drain_server_tasks(&drain_state, bg_tasks).await;
    });
    // Past the 2 s grace: an abortable listener has been aborted by now.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let drain_waited = !drain.is_finished();
    pause.release();
    tokio::time::timeout(WAIT, drain).await??;
    Ok(StopOutcome {
        drain_waited,
        persisted: persisted_has(path, applied_marker),
        temp_files: leftover_temp_files(path),
    })
}

/// Install one group that the local agent administers and persist it, so
/// the file holds the state before the listener's apply.
async fn install_group(
    state: &Arc<AppState>,
    metadata_topic: &str,
) -> Result<x0x::groups::GroupInfo> {
    let (mut info, admin_hex, _) = metadata_terminality_test_group(state, GROUP);
    info.genesis = Some(x0x::groups::state_commit::GroupGenesis::with_existing_id(
        STABLE.to_string(),
        admin_hex,
        info.created_at,
        String::new(),
    ));
    info.metadata_topic = metadata_topic.to_string();
    info.recompute_state_hash();
    state
        .named_groups
        .write()
        .await
        .insert(GROUP.to_string(), info.clone());
    anyhow::ensure!(
        save_named_groups(state).await,
        "the group is persisted before the listener's apply"
    );
    anyhow::ensure!(!persisted_has(&state.named_groups_path, RENAMED));
    Ok(info)
}

/// A signed rename of `parent` by the local admin. Its apply persists the
/// roster through the atomic named-groups write.
fn rename_event(state: &Arc<AppState>, parent: &x0x::groups::GroupInfo) -> NamedGroupMetadataEvent {
    let mut next = parent.clone();
    next.name = RENAMED.to_string();
    next.roster_revision += 1;
    NamedGroupMetadataEvent::GroupMetadataUpdated {
        group_id: STABLE.to_string(),
        revision: next.roster_revision,
        actor: hex::encode(state.agent.agent_id().as_bytes()),
        name: Some(next.name.clone()),
        description: None,
        commit: Some(sign_metadata_terminality_commit(
            parent,
            &next,
            state,
            now_millis_u64(),
        )),
    }
}

async fn in_memory_name(state: &AppState) -> Option<String> {
    state
        .named_groups
        .read()
        .await
        .get(GROUP)
        .map(|info| info.name.clone())
}

/// The direct-channel metadata listener (`run_direct_metadata_listener`)
/// receives a rename, and its apply parks inside the named-groups write.
/// Shutdown must not abort that apply: the drain waits past the grace, the
/// write completes, the file holds the rename and no temp file is left.
/// No socket: the event is injected into the agent's direct-message bus.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1275_direct_metadata_listener_apply_is_not_aborted_mid_write() -> Result<()> {
    let (state, _dir) = secure_endpoint_test_state().await?;
    let parent = install_group(&state, "local:1275-direct-metadata").await?;
    let path = state.named_groups_path.clone();
    let listener = tokio::spawn(run_direct_metadata_listener(
        Arc::clone(&state),
        state.agent.subscribe_direct(),
    ));
    let pause = atomic_write_test_seam::arm(&path);
    let delivered = state
        .agent
        .direct_messaging()
        .handle_incoming(
            state.agent.machine_id(),
            state.agent.agent_id(),
            serde_json::to_vec(&rename_event(&state, &parent))?,
            true,
            None,
            None,
        )
        .await;
    anyhow::ensure!(delivered >= 1, "the listener is subscribed");
    anyhow::ensure!(
        wait_reached(&pause).await,
        "the listener's apply parks in its named-groups write"
    );

    let outcome = stop_while_write_parked(&state, vec![listener], &pause, &path, RENAMED).await?;
    assert!(
        outcome.apply_completed(),
        "the listener's apply must finish its write at shutdown: {outcome:?}"
    );
    assert_eq!(in_memory_name(&state).await.as_deref(), Some(RENAMED));
    Ok(())
}

/// The per-group metadata topic listener (`ensure_named_group_metadata_listener`)
/// receives the same rename on a local topic, with the same expectations.
/// The shutdown drain collects this listener from `group_metadata_tasks`.
/// A listener installed after the drain took the registries (as a shielded
/// apply that is still running could) is refused, so none outlives the stop.
/// Socket test (the gossip runtime needs a bound endpoint): loopback only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1275_group_metadata_listener_apply_is_not_aborted_mid_write() -> Result<()> {
    let (state, _dir) = networked_test_state("1275-group-metadata-listener").await?;
    let topic = "local:1275-group-metadata";
    let parent = install_group(&state, topic).await?;
    let path = state.named_groups_path.clone();
    ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
    anyhow::ensure!(
        state.group_metadata_tasks.read().await.contains_key(GROUP),
        "the group's metadata listener is installed"
    );
    let pause = atomic_write_test_seam::arm(&path);
    state
        .agent
        .publish(topic, serde_json::to_vec(&rename_event(&state, &parent))?)
        .await?;
    anyhow::ensure!(
        wait_reached(&pause).await,
        "the listener's apply parks in its named-groups write"
    );

    let outcome = stop_while_write_parked(&state, Vec::new(), &pause, &path, RENAMED).await?;
    assert!(
        outcome.apply_completed(),
        "the listener's apply must finish its write at shutdown: {outcome:?}"
    );
    assert_eq!(in_memory_name(&state).await.as_deref(), Some(RENAMED));

    ensure_named_group_metadata_listener(Arc::clone(&state), GROUP).await;
    assert!(
        !state.group_metadata_tasks.read().await.contains_key(GROUP),
        "no metadata listener is installed after the drain"
    );
    spawn_public_message_listener(Arc::clone(&state), "1275-late-public".to_string()).await;
    assert!(
        state.public_message_tasks.read().await.is_empty(),
        "no public-message listener is installed after the drain"
    );
    Ok(())
}
