//! #1269 r2: the shutdown drain (`crate::server::drain_server_tasks`) must
//! never abort a group-state apply in the middle of its persistence. Each
//! test parks a real named-groups atomic write after its temp file is synced
//! and before the rename (a slow write), stops the daemon's tasks while it
//! is parked, and then checks what is on disk. No socket is used.

use super::*;

/// How long a test waits for a parked write to be reached, or for a drain.
const WAIT: Duration = Duration::from_secs(15);

/// A test daemon state with one in-memory group that is not yet on disk.
async fn state_with_unsaved_group() -> Result<(Arc<AppState>, tempfile::TempDir, String)> {
    let (state, dir) = secure_endpoint_test_state().await?;
    let group_key = "69".repeat(32);
    state.named_groups.write().await.insert(
        group_key.clone(),
        x0x::groups::GroupInfo::with_policy(
            group_key.clone(),
            String::new(),
            state.agent.agent_id(),
            group_key.clone(),
            x0x::groups::GroupPolicyPreset::PublicOpen.to_policy(),
        ),
    );
    Ok((state, dir, group_key))
}

async fn wait_reached() -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !atomic_write_test_seam::reached() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Temp files of an unfinished atomic write next to `path`.
fn leftover_temp_files(path: &FsPath) -> Vec<String> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let prefix = format!("{name}.");
    std::fs::read_dir(path.parent().unwrap_or(FsPath::new(".")))
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
                .filter(|file| file.starts_with(&prefix) && file.ends_with(".tmp"))
                .collect()
        })
        .unwrap_or_default()
}

fn persisted_has(path: &FsPath, group_key: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|json| json.contains(group_key))
}

/// A shielded apply parked inside its atomic write when shutdown starts is
/// awaited past the 2 s grace, never aborted: the write completes, the file
/// holds the new state, no temp file is left, and later applies are
/// refused unrun.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1269_drain_never_aborts_a_shielded_apply_mid_write() -> Result<()> {
    let (state, _dir, group_key) = state_with_unsaved_group().await?;
    let path = state.named_groups_path.clone();
    atomic_write_test_seam::arm(&path);
    let (saved_tx, saved_rx) = tokio::sync::oneshot::channel();
    let apply_state = Arc::clone(&state);
    assert!(state.spawn_shielded(async move {
        let _ = saved_tx.send(save_named_groups(&apply_state).await);
    }));
    assert!(wait_reached().await, "the write parks before its rename");

    let drain_state = Arc::clone(&state);
    let drain = tokio::spawn(async move {
        crate::server::drain_server_tasks(&drain_state, Vec::new()).await;
    });
    // Past the 2 s grace: an abortable task would have been aborted by now.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert!(
        !drain.is_finished(),
        "the drain must wait for a shielded apply, not abort it"
    );
    assert!(!persisted_has(&path, &group_key), "still parked");
    atomic_write_test_seam::release();
    tokio::time::timeout(WAIT, drain).await??;

    assert!(saved_rx.await?, "the parked write completes durably");
    assert!(
        persisted_has(&path, &group_key),
        "the persisted file holds the applied state"
    );
    assert_eq!(leftover_temp_files(&path), Vec::<String>::new());
    // Admission closed when the drain started: a later apply never runs.
    let (ran_tx, mut ran_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(!state.spawn_shielded(async move {
        let _ = ran_tx.send(());
    }));
    assert!(
        ran_rx.try_recv().is_err(),
        "a refused apply is dropped unrun"
    );
    assert!(state.run_shielded(async {}).await.is_none());
    Ok(())
}

/// Negative control: the same write in an abortable (detached) task is
/// aborted at the end of the grace, in the middle of the write. The file
/// never receives the state and the synced temp file is left behind. This
/// is why a persisting apply must not be detached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1269_drain_aborts_a_detached_task_mid_write() -> Result<()> {
    let (state, _dir, group_key) = state_with_unsaved_group().await?;
    let path = state.named_groups_path.clone();
    atomic_write_test_seam::arm(&path);
    let apply_state = Arc::clone(&state);
    assert!(state.spawn_detached(async move {
        let _ = save_named_groups(&apply_state).await;
    }));
    assert!(wait_reached().await, "the write parks before its rename");

    let started = tokio::time::Instant::now();
    tokio::time::timeout(WAIT, crate::server::drain_server_tasks(&state, Vec::new())).await?;
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "the drain gives the grace first"
    );
    atomic_write_test_seam::release();
    assert!(
        !persisted_has(&path, &group_key),
        "the aborted write never reached its rename"
    );
    assert_eq!(
        leftover_temp_files(&path).len(),
        1,
        "the aborted write leaves its temp file behind"
    );
    Ok(())
}
