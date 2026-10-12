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

pub(super) async fn wait_reached(pause: &atomic_write_test_seam::WritePause) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !pause.reached() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    true
}

/// Temp files of an unfinished atomic write next to `path`.
pub(super) fn leftover_temp_files(path: &FsPath) -> Vec<String> {
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

pub(super) fn persisted_has(path: &FsPath, group_key: &str) -> bool {
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
    let pause = atomic_write_test_seam::arm(&path);
    let (saved_tx, saved_rx) = tokio::sync::oneshot::channel();
    let apply_state = Arc::clone(&state);
    assert!(state.spawn_shielded(async move {
        let _ = saved_tx.send(save_named_groups(&apply_state).await);
    }));
    assert!(
        wait_reached(&pause).await,
        "the write parks before its rename"
    );

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
    pause.release();
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
    let pause = atomic_write_test_seam::arm(&path);
    let apply_state = Arc::clone(&state);
    assert!(state.spawn_detached(async move {
        let _ = save_named_groups(&apply_state).await;
    }));
    assert!(
        wait_reached(&pause).await,
        "the write parks before its rename"
    );

    let started = tokio::time::Instant::now();
    tokio::time::timeout(WAIT, crate::server::drain_server_tasks(&state, Vec::new())).await?;
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "the drain gives the grace first"
    );
    pause.release();
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

/// A shielded apply can be inside the joiner's Welcome fetch when shutdown
/// starts. That wait (up to 115 s) must end at once, as on a lost peer, so
/// the drain does not wait out a Welcome whose listener has stopped; its
/// receive and waiter registrations are removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1269_welcome_fetch_ends_when_shutdown_starts() -> Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let bytes = b"Welcome that never arrives".to_vec();
    let welcome_id = welcome_id_for_bytes(&bytes);
    let welcome_ref = WelcomeRef {
        welcome_id: welcome_id.clone(),
        byte_len: bytes.len() as u64,
        source: hex::encode(owner.agent.agent_id().as_bytes()),
    };
    let fetch_state = Arc::clone(&joiner);
    let fetch = tokio::spawn(async move {
        fetch_treekem_welcome_via_schedule(
            &fetch_state,
            &"ef".repeat(32),
            &welcome_ref,
            |_, _| async { Ok(()) },
            &[Duration::ZERO, Duration::from_secs(30)],
            WELCOME_FETCH_TIMEOUT,
        )
        .await
    });
    let deadline = tokio::time::Instant::now() + WAIT;
    while !joiner
        .pending_welcome_waiters
        .read()
        .await
        .contains_key(&welcome_id)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fetch registers"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let started = tokio::time::Instant::now();
    joiner.shutdown_started.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), fetch).await??;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(result, Err(WELCOME_FETCH_SHUTDOWN.to_string()));
    assert!(joiner.pending_welcome_waiters.read().await.is_empty());
    assert!(joiner.pending_welcome_receives.read().await.is_empty());
    // A fetch that starts after shutdown began ends before it registers.
    let late_ref = WelcomeRef {
        welcome_id: welcome_id_for_bytes(b"late"),
        byte_len: 4,
        source: hex::encode(owner.agent.agent_id().as_bytes()),
    };
    let late = fetch_treekem_welcome_via_schedule(
        &joiner,
        &"ef".repeat(32),
        &late_ref,
        |_, _| async { Ok(()) },
        &[Duration::ZERO],
        WELCOME_FETCH_TIMEOUT,
    )
    .await;
    assert_eq!(late, Err(WELCOME_FETCH_SHUTDOWN.to_string()));
    assert!(joiner.pending_welcome_receives.read().await.is_empty());
    Ok(())
}

/// r3: the Welcome request send itself can wait about 24 s on a missing
/// receipt. A send that is in progress when shutdown starts must end at
/// once too, with the same cleanup, and without being awaited further.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue1269_welcome_fetch_send_ends_when_shutdown_starts() -> Result<()> {
    let (joiner, _joiner_dir) = secure_endpoint_test_state().await?;
    let (owner, _owner_dir) = secure_endpoint_test_state().await?;
    let welcome_id = welcome_id_for_bytes(b"Welcome whose request never returns");
    let welcome_ref = WelcomeRef {
        welcome_id: welcome_id.clone(),
        byte_len: 35,
        source: hex::encode(owner.agent.agent_id().as_bytes()),
    };
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let started_tx = std::sync::Mutex::new(Some(started_tx));
    let fetch_state = Arc::clone(&joiner);
    let fetch = tokio::spawn(async move {
        fetch_treekem_welcome_via_schedule(
            &fetch_state,
            &"ef".repeat(32),
            &welcome_ref,
            move |_, _| {
                // The injected sender signals that it is sending, then
                // blocks like a send whose receipt never arrives.
                if let Some(tx) = started_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = tx.send(());
                }
                std::future::pending::<std::result::Result<(), WelcomeFetchSendError>>()
            },
            &[Duration::ZERO, Duration::from_secs(30)],
            WELCOME_FETCH_TIMEOUT,
        )
        .await
    });
    tokio::time::timeout(WAIT, started_rx).await??;
    assert!(
        joiner
            .pending_welcome_waiters
            .read()
            .await
            .contains_key(&welcome_id),
        "the fetch is registered while its request is in flight"
    );
    let started = tokio::time::Instant::now();
    joiner.shutdown_started.cancel();
    let result = tokio::time::timeout(Duration::from_secs(2), fetch).await??;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(result, Err(WELCOME_FETCH_SHUTDOWN.to_string()));
    assert!(joiner.pending_welcome_waiters.read().await.is_empty());
    assert!(joiner.pending_welcome_receives.read().await.is_empty());
    Ok(())
}
